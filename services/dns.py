#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging

if __name__ == '__main__':
    from lib.mplog import setup_logging
    setup_logging()

import socket
import re
import sys
import os
import time
from multiprocessing import Process

logger = logging.getLogger("service.dns")

try:
    import dnslib
except ImportError:
    logger.critical("Unable to import dnslib, install with 'pip3 install dnslib'")
    sys.exit(1)

import sanic
from sanic import Sanic

from lib import ipc
from lib import procs
from lib.constants import *
from lib import network


class DNSAPI:
    def __init__(self):
        self.dns_server = DNSServer()
        self.proc = None
        self.app = None
        self.socket = None
        self.config = {}
        self.dynamic = {}
        self.dns_running = False

    def run(self):
        self.get_config()

        self.set_ip_mappings()

        self.socket = ipc.unix_socket(SOCKET_DNS)
        self.proc = Process(
            target=self.dns_server.udp_server,
            args=(
                self.config["DNSAPI"].get("bind", "0.0.0.0"),
                int(self.config["DNSAPI"].get("port", 53)),
                self.dns_server,
            )
        )
        self.proc.start()

        self.app = Sanic("DNSAPI")
        self.add_routes()

        logger.info("Initialized DNS module")
        self.app.run(sock=self.socket, access_log=False)

    def add_routes(self):
        self.app.add_route(
            self.add_dynamic,
            "/add/dynamic/<domain>/<ip_addr>",
            methods=["POST"]
        )

        self.app.add_route(
            self.add_dynamic_ms,
            "/add/dynamic/ms/<domain>/<ip_addr>",
            methods=["POST"]
        )

        self.app.add_route(
            self.get_dynamic,
            "/get/dynamic/<domain>",
            methods=["GET"]
        )

        self.app.add_route(
            self.set_dns_server_status,
            "/set/dns/server/running/<status:[a-z]+>",
            methods=["POST"]
        )

        self.app.add_route(self.stop, "/exit", methods=["POST"])
        self.app.add_route(self.status, "/status", methods=["GET"])
        self.app.add_route(self.revert, "/revert", methods=["POST"])

    def set_ip_mappings(self):
        assert "root" in self.config["DNSAPI"] and "publicip" in self.config["DNSAPI"]

        publicip = self.config["DNSAPI"]["publicip"]
        root_list = self.config["DNSAPI"]["root"]
        roots = root_list.split(",")
        for root in roots:
            self.dns_server.add_static(root, publicip)

            for sub in self.config["DNSAPI"].get("subdomains", "www,ns1,ds2").split(","):
                self.dns_server.add_static(sub.strip() + "." + root, publicip)

            self.dns_server.add_wildcard(r".*\." + root, publicip)

    def get_config_entry(self, section):
        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/{}".format(section))
        ipc.assert_response_valid(response, dict)
        self.config[section] = response["text"].copy()

    def get_config(self):
        self.get_config_entry("DNSAPI")

    async def set_dns_server_status(self, _request, status):
        logger.debug("Received a change in DNS status, server is: {}".format(status))
        if status == "up":
            self.dns_running = True
        else:
            self.dns_running = False
        return sanic.response.json({"response": "OK"})

    async def get_dynamic(self, request, domain):
        ip = self.dynamic.get(domain, "")
        logger.debug("dynamic query {} -> {}".format(domain, ip))
        return sanic.response.json({"ip": ip})

    async def add_dynamic_ms(self, request, domain, ip_addr):
        logger.debug("Set dynamic MS {} -> {}".format(domain, ip_addr))
        self.dynamic[domain] = [self.config["DNSAPI"]["publicip"], ip_addr]
        return sanic.response.json(RETURN_OK)

    async def add_dynamic(self, request, domain, ip_addr):
        logger.debug("Set dynamic {} -> {}".format(domain, ip_addr))
        self.dynamic[domain] = ip_addr
        return sanic.response.json(RETURN_OK)

    async def status(self, request):
        if self.dns_running is True:
            return sanic.response.json({"status": "up"})

        return sanic.response.json({"status": "down"})

    async def stop(self, request):
        self.app.stop()
        self.socket.close()
        self.proc.terminate()
        return sanic.response.json({"status": "stopped"})

    async def revert(self, request):
        self.dynamic = {}
        return sanic.response.json({"response": "OK"})


class DNSServer:
    """
    Authoritative DNS server that only responds to queries under 1 root domain.

    This DNS can be dynamically changed during runtime to give different
    responses based on external factors.
    """
    def __init__(self):
        self.port = 53

        self.ttl = 5

        # Search order is:
        # 1. static
        # 2. dynamic
        # 3. wildcard
        self.static = {}
        self.wildcard = []

    def add_wildcard(self, domain, ip_addr):
        """
        Add a regular expression for a domain that should be match, like
        r'[a-zA-Z0-9]\.example\.com'.
        """
        self.wildcard.append({"domain": domain, "ip": ip_addr})

    def add_static(self, domain, ip_addr):
        """ Add a domain to IP-address mapping. """
        self.static[domain] = ip_addr

    def find_wildcard(self, qname):
        ret = None
        for i in self.wildcard:
            match = re.match(i.get("domain", ""), qname)
            if match:
                ret = i.get("ip")
                break
        return ret

    @staticmethod
    def domain2ip(qdomain, ips, ttl):
        ans = []
        if isinstance(ips, list):
            for ip_addr in ips:
                ans.append(
                    dnslib.RR(
                        qdomain,
                        rdata=dnslib.A(ip_addr),
                        ttl=ttl
                    )
                )
        elif isinstance(ips, str):
            ans.append(
                dnslib.RR(
                    qdomain,
                    rdata=dnslib.A(ips),
                    ttl=ttl
                )
            )

        return ans

    @staticmethod
    def get_dynamic(domain):
        response = ipc.sync_http_raw("GET", SOCK_DNS, "/get/dynamic/{}".format(domain))
        try:
            resp = response["text"]
        except:
            logger.warning("Unable to check for dynamic domain")
            return ""
        if isinstance(resp, dict):
            return resp.get("ip", "")
        return ""

    @staticmethod
    def match_internal_ip(domain):
        match = re.match("^(([0-9]{1,3}\.){4}).*", domain)
        if match:
            ip = match.group(1)[:-1]
            if network.internal_ip(ip):
                return ip
        return None

    def find_answers(self, question):
        ans = []

        # Multiple questions in query is not supported, but we still continue with response
        if len(question.questions) > 1:
            logger.warning("Received a DNS query with multiple questions, that is not supported")

        # Always answer first 'A' question
        for i in range(0, len(question.questions)):
            if question.questions[i].qtype != dnslib.QTYPE.A:
                continue

            qstr = str(question.questions[i].get_qname()).lower()
            logger.info("DNS query: %s", qstr)
            domain = qstr[:-1]

            if domain in self.static:
                ans = DNSServer.domain2ip(domain, self.static[domain], self.ttl)
            else:
                dynamic = DNSServer.get_dynamic(domain)
                if dynamic != "":
                    ans = DNSServer.domain2ip(domain, dynamic, self.ttl)
                else:
                    # We first try and match to an IP address, like 127.0.0.1.root
                    ip = DNSServer.match_internal_ip(domain)
                    if ip != None:
                        ans = DNSServer.domain2ip(domain, ip, self.ttl)
                    else:
                        ret = self.find_wildcard(domain)
                        ans = DNSServer.domain2ip(domain, ret, self.ttl)
            return ans
        return ans

    def answer(self, data, client):
        try:
            question = dnslib.DNSRecord.parse(data)
        except:
            logger.warning("Unable to parse DNS packet from: %s", client)
            return None

        ans = self.find_answers(question)

        ret = question.reply()
        for i in ans:
            ret.add_answer(i)

        return ret.pack()

    def udp_server(self, ip, port, dns):
        logger.info("Starting DNS server at %s:%i", ip, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (ip, port)

        try:
            sock.bind(server_address)
        except Exception as e:
            logger.warning("Unable to bind to socket, message: {}".format(e))
            sys.exit(1)

        # This server might start up before the DNS management server so we must try a couple of
        # times.
        for i in range(0, 5):
            try:
                response = ipc.sync_http_raw("POST", SOCK_DNS, "/set/dns/server/running/up")
                if reponse["text"]["status"] == "OK":
                    break
            except:
                time.sleep(0.5)
                continue
            break

        while True:
            try:
                data, client = sock.recvfrom(4096)
                logger.info("Connection from: {}".format(client[0]))
            except:
                logger.info("Closing the connection")
                sock.close()
                break
            if data:
                data = dns.answer(data, client[0])
                if data is not None:
                    sock.sendto(data, client)

if __name__ == '__main__':
    def server_up():
        resp = ipc.sync_http_raw("GET", SOCK_DNS, "/status")
        if ipc.response_valid(resp, dict) and resp["text"].get("status") == "up":
            logger.info("DNS service has successfully started")
        else:
            logger.error("Unable to start DNS service")
            _resp = ipc.sync_http_raw("POST", SOCK_DNS, "/exit")
            sys.exit(1)

    resp = procs.wait_service_up(SOCK_CONFIG)
    if resp is True:
        import threading
        threading.Timer(5, server_up, ()).start()
        dns = DNSAPI()
        dns.run()
    else:
        logger.error("Config service was not ready")
        sys.exit(1)
