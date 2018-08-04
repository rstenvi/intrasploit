#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import logging

if __name__ == '__main__':
    from lib.mplog import setup_logging
    setup_logging()

import sys

import sanic
from sanic import Sanic
from sanic.exceptions import ServerError
from tinydb import TinyDB, Query

from lib import ipc
from lib import procs
from lib import misc
from lib.constants import *

logger = logging.getLogger("service.database")

class Database:
    """
    A database of all connected clients and any data they might have harvested.
    """
    def __init__(self):
        self.db = None
        self.app = None
        self.socket = None
        self.database = {}
        self.clients = {}

    def run(self):
        response = ipc.sync_http_raw(
            "GET",
            SOCK_CONFIG,
            "/get/variable/Database/storage"
        )
        assert isinstance(response, dict) and "text" in response
        dbfile = response["text"].get("storage", None)
        assert dbfile is not None
        self.db = TinyDB(dbfile)

        self.socket = ipc.unix_socket(SOCKET_DATABASE)
        self.app = Sanic("Database")
        self.add_routes()
        logger.info("Initialized database module")
        self.app.run(sock=self.socket, access_log=False)

    def add_routes(self):
        self.app.add_route(self.stop, '/exit', methods=["POST"])
        self.app.add_route(self.status, '/status', methods=["GET"])

        self.app.add_route(self.client_exist, "/client/exist/<client>", methods=["GET"])
        self.app.add_route(self.new_client, "/new/client/<client>/<ip>", methods=["POST"])
        self.app.add_route(self.delete_client, "/delete/client/<client>", methods=["POST"])
        self.app.add_route(self.new_attack, "/new/attack/value/<parent>/<child>/<lip>/<lport>", methods=["POST"])

        self.app.add_route(self.purge, "/purge", methods=["POST"])

        self.app.add_route(self.store_json, "/store/json/<client>/<key>", methods=["POST"])
        self.app.add_route(self.store_body, "/store/body/<client>/<key>", methods=["POST"])
        self.app.add_route(self.store_value, "/store/value/<client>/<key>/<value>", methods=["POST"])

        self.app.add_route(self.append_value, "/append/value/<client>/<key>/<value>", methods=["POST"])
        self.app.add_route(self.append_list, "/append/list/<client>/<key>", methods=["POST"])
        self.app.add_route(self.merge_json, "/merge/json/<client>/<key>", methods=["POST"])
        self.app.add_route(self.append_body, "/append/body/<client>/<key>", methods=["POST"])

        self.app.add_route(self.get_json, "/get/json/<client>/<key>", methods=["GET"])
        self.app.add_route(self.get_value, "/get/value/<client>/<key>", methods=["GET"])
        self.app.add_route(self.get_clients, "/get/clients", methods=["GET"])
        self.app.add_route(self.get_client, "/get/client/<client>", methods=["GET"])

        self.app.add_route(self.pop_value, "/pop/value/<client>/<key>", methods=["POST"])
        self.app.add_route(self.peek_value, "/peek/value/<client>/<key>", methods=["GET"])

    async def purge(self, request):
        self.db.purge()
        return sanic.response.json(RETURN_OK)

    async def client_exist(self, request, client):
        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw("Not found", status=404)
        return sanic.response.json({"status":"found"})

    # Delete all data belonging to a client
    async def delete_client(self, request, client):
        self.db.remove(Query().parent == client)
        self.db.remove(Query().id == client)
        return sanic.response.json(RETURN_OK)

    # On first visit / redirect
    async def new_client(self, request, client, ip):
        self.db.insert({"id": client, "ip": ip, "father":True})
        return sanic.response.json(RETURN_OK)

    async def store_json(self, request, client, key):
        data = request.json
        self.db.update({key: data}, Query().id == client)
        return sanic.response.json(RETURN_OK)

    async def get_json(self, request, client, key):
        data = self.db.search(Query().id == client)
        if len(data) != 1 or key not in data[0]:
            logger.warning("Unable to find client {} and/or key {}".format(client, key))
            return sanic.response.raw(b"", status=404)
        return sanic.response.json(data[0][key])

    async def get_value(self, request, client, key):
        data = self.db.search(Query().id == client)
        if len(data) != 1 or key not in data[0]:
            logger.warning("Unable to find client {} and/or key {}".format(client, key))
            return sanic.response.raw(b"", status=404)
        return sanic.response.json({key: data[0][key]})

    async def store_body(self, request, client, key):
        data = request.body
        self.db.update({key: data}, Query().id == client)
        return sanic.response.json(RETURN_OK)

    async def store_value(self, request, client, key, value):
        self.db.update({key: value}, Query().id == client)
        return sanic.response.json(RETURN_OK)

    async def append_value(self, request, client, key, value):
        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)

        subs = entries[0].get(key, [])
        subs.apend(value)
        self.db.update({key: subs}, Query().id == client)

        return sanic.response.json(RETURN_OK)

    async def append_list(self, request, client, key):
        value = request.json
        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)

        subs = entries[0].get(key, [])
        for val in value:
            subs.append(val)
        self.db.update({key: subs}, Query().id == client)

        return sanic.response.json(RETURN_OK)

    async def merge_json(self, request, client, key):
        value = request.json

        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)

        subs = entries[0].get(key, {})
        for key, val in value.items():
            subs[key] = val
        self.db.update({key: subs}, Query().id == client)

        return sanic.response.json(RETURN_OK)

    async def append_body(self, request, client, key):
        value = request.body

        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)

        subs = entries[0].get(key, [])
        subs.append(value)
        self.db.update({key: subs}, Query().id == client)

        return sanic.response.json(RETURN_OK)

    def get_last_value(self, client, key):
        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)

        subs = entries[0].get(key, [])
        try:
            ret = subs.pop()
        except:
            return None, None
        return (ret, subs)

    async def get_client(self, request, client):
        entries = self.db.search(Query().id == client)
        if len(entries) != 1:
            logger.warning("Unable to find client {}".format(client))
            return sanic.response.raw(b"", status=404)
        return sanic.response.json(entries[0])

    async def get_clients(self, request):
        full = self.db.all()
        ret = {}
        for f in full:
            if "parent" not in f:
                ret[f["id"]] = {}
                ret[f["id"]]["childs"] = []
                ret[f["id"]]["browser"] = f.get("browser", "unknown")
                ret[f["id"]]["publicip"] = f.get("publicip", "unknown")

        for f in full:
            if "parent" in f:
                ins = {
                    "connected": f.get("connected", "unknown"),
                    "port": f.get("port", "unknown"),
                    "ip": f.get("ip", "unknown"),
                    "id": f.get("id", "unknown")
                }
                ret[f["parent"]]["childs"].append(ins)
        return sanic.response.json(ret)

    async def pop_value(self, request, client, key):
        ret, subs = self.get_last_value(client, key)
        if ret != None:
            # Write value back
            self.db.update({key: subs}, Query().id == client)
            return sanic.response.raw(ret.encode())
        return sanic.response.raw(b"", status=404)

    async def peek_value(self, request, client, key):
        ret, _subs = self.get_last_value(client, key)
        if ret != None:
            return sanic.response.raw(ret.encode())
        return sanic.response.raw(b"")

    async def new_attack(self, request, parent, child, lip, lport):
        self.db.insert({"id": child, "ip": lip, "port": lport, "parent": parent})

        return sanic.response.json(RETURN_OK)

    def ensure_client_exists(self, client):
        if client not in self.clients:
            self.clients[client] = {}

    async def get_browser(self, request, client):
        browser = self.clients.get(client, {}).get("browser", "Unknown")
        return sanic.response.json({"browser": browser})

    async def add_ports(self, request, client, localip):
        if client not in self.clients:
            self.clients[client] = {}
        if localip not in self.clients[client]:
            self.clients[client][localip] = {}
            self.clients[client][localip]["open"] = []
        ports = request.json
        for port in ports:
            self.clients[client][localip]["open"].append(ports)

        return sanic.response.json(RETURN_OK)

    async def status(self, _request):
        return sanic.response.json(RETURN_UP)

    async def stop(self, _request):
        self.app.stop()
        self.socket.close()
        logger.info("Stopping database-service")
        return sanic.response.json(RETURN_STOPPED)

if __name__ == '__main__':
    resp = procs.wait_service_up(SOCK_CONFIG)
    if resp is True:
        db = Database()
        db.run()
    else:
        logger.error("Config service was not ready")
        sys.exit(1)
