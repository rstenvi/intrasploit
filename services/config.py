#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import configparser
import logging

import sanic
from sanic import Sanic
from sanic.exceptions import ServerError

from lib import ipc
from lib.constants import *

logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.optionxform = str   # Preserve case on names
        self.app = None
        self.socket = None

    def run(self, file_name):
        logger.debug("Running config-service")
        self.socket = ipc.unix_socket(SOCKET_CONFIG)
        self.app = Sanic("Config")
        self.config.read(file_name)
        self.add_routes()
        logger.info("Done initializing config module")
        self.app.run(sock=self.socket, access_log=False)

    def add_routes(self):
        self.app.add_route(self.stop, '/exit', methods=["POST"])
        self.app.add_route(self.status, '/status', methods=["GET"])
        self.app.add_route(
            self.get_variable,
            '/get/variable/<section:[a-zA-Z0-9]+>/<key:[a-zA-Z0-9]+>',
            methods=["GET"]
        )

        self.app.add_route(
            self.get_section,
            '/get/section/<section:[a-zA-Z0-9]+>',
            methods=["GET"]
        )

        self.app.add_route(
            self.set_variable,
            '/set/variable/<section:[a-zA-Z0-9]+>',
            methods=["POST"]
        )

    async def status(self, _request):
        return sanic.response.json(RETURN_UP)

    async def stop(self, _request):
        self.app.stop()
        self.socket.close()
        logger.info("Stopping config-service")
        return sanic.response.json(RETURN_STOPPED)

    async def get_section(self, _request, section):
        if section not in self.config:
            raise ServerError("Section '{}' not in config".format(section), status_code=500)

        return sanic.response.json(dict(self.config[section]))

    async def get_variable(self, _request, section, key):
        if section not in self.config:
            raise ServerError("Section not in config", status_code=500)
        if key not in self.config[section]:
            raise ServerError("Key not in section", status_code=500)

        return sanic.response.json({key: self.config[section][key]})

    async def set_variable(self, request, section):
        if section not in self.config:
            raise ServerError("Section not in config", status_code=500)
        for key, value in request.raw_args.items():
            self.config[section][key] = value

        return sanic.response.json(RETURN_OK)
