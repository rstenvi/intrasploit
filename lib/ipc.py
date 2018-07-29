#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import os
import socket
import json
import urllib
import logging

import aiohttp
from aiohttp import ClientSession
import requests
import requests_unixsocket

from lib.constants import SOCKET_SD, SOCKET_DNS, SOCKET_MODULES, SOCKET_CONFIG, SOCKET_WEBSERVER

logger = logging.getLogger(__name__)

def unix_socket(unix_file):
    try:
        os.unlink(unix_file)
    except OSError:
        if os.path.exists(unix_file):
            raise
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(unix_file)
    return sock


def response2return(response):
    if response.status_code == 200:
        try:
            return response.json()
        except:
            return response.text
    else:
        return None


def parse_response(response):
    try:
        return json.loads(response.decode())
    except:
        return response.decode()


def file2request(unix_file, query):
    fname = urllib.parse.quote_plus(unix_file)
    return "http+unix://{}{}".format(fname, query)


def get_connector(path):
    return aiohttp.UnixConnector(path=path)

async def aiohttp2response(response):
    data = await response.text()
    try:
        data = json.loads(data)
    except:
        pass

    return {
        "status": response.status,
        "text": data,
        'headers': response.headers
    }

async def async_http_raw(method, url, path, data=None):
    logger.debug("async http raw: {} {}{}".format(method, url, path))
    if url.startswith("http+unix://"):
        unix_file = url[len("http+unix://"):]
        conn = aiohttp.UnixConnector(path=unix_file)
        path = "http://localhost" + path
    else:
        conn = None
        path = url + path

    async with ClientSession(connector=conn) as session:
        if method == "GET":
            async with session.get(path) as response:
                return await aiohttp2response(response)

        elif method == "POST":
            async with session.post(path, data=data) as response:
                return await aiohttp2response(response)
        else:
            logger.critical("Invalid HTTP method")
            raise


def sync_http_raw(method, url, path, data=None):
    logger.debug("sync http raw: {} {}{}".format(method, url, path))
    if url.startswith("http+unix://"):
        session = requests_unixsocket.Session()
        url = url[len("http+unix://"):]
        url = urllib.parse.quote_plus(url)
        path = "http+unix://" + url + path
    else:
        session = requests.Session()
        path = url + path

    response = None
    with session:
        if method == "GET":
            response = session.get(path)
        elif method == "POST":
            response = session.post(path, data)
    if response != None:
        try:
            data = json.loads(response.text)
        except:
            data = response.text
        return {
            "status": response.status_code,
            "headers": response.headers,
            "text": data
        }
    return None


def assert_response_valid(response, rtype):
    assert isinstance(response, dict)
    assert response["status"] == 200
    assert isinstance(response["text"], rtype)
