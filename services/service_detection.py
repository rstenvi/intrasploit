#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


import re
import logging
import base64

import sanic
from sanic import Sanic
from sanic.exceptions import ServerError

from lib import ipc
from lib.constants import *

logger = logging.getLogger(__name__)


class NmapParser:
    def __init__(self):
        self.requests = []

    def add_file(self, nmap_file):
        self.parse_file(nmap_file)

    def get_queries(self, port):
        """ Get a list of all queries that should be sent to a port. """
        ret = []
        try:
            port = int(port)
        except ValueError:
            logger.error("Unable to convert '%s' to int", port)
            return []

        for request in self.requests:
            if port in request["ports"] or NmapParser.port_in_ranges(port, request["ranges"]):
                ins = request["query"]
                ins["id"] = request["id"]
                ret.append(ins)
        return ret

    @staticmethod
    def test2grouphits(response_lines, matches):
        ret = []
        for match in matches:
            for line in response_lines:
                rem = match.match(line)
                if line != "" and rem:
                    for i in rem.groups():
                        ret.append(i)
        return ret

    @staticmethod
    def replace_product_vars(product, variables):
        for key, val in product.items():
            repl = re.findall(r"\$[0-9]+", val)
            for rep in repl:
                num = int(rep[1:])
                try:
                    product[key] = val.replace(rep, variables[num-1])
                except:
                    logger.error(
                        "Unable to replace text %i %s %s %s",
                        num, variables, product, repl
                    )
        return product

    def find_matches_id(self, response, ID):
        ret = []
        lines = response.split("\r\n")
        for tests in self.requests[ID].get("tests", []):
            found_matches = 0
            tests_m = tests.get("matches", None)
            if tests_m is None:
                continue

            for test in tests_m:
                for line in lines:
                    if line != "" and test.match(line):
                        found_matches += 1
                        break

            if found_matches == len(tests_m):
                grouphits = NmapParser.test2grouphits(lines, tests_m)
                ret.append(
                    NmapParser.replace_product_vars(
                        tests.get("product", {}).copy(),
                        grouphits
                    )
                )
        return ret

    def find_matches(self, response):
        ret = []
        for i in range(0, len(self.requests)):
            resp = self.find_matches_id(response, i)
            for r in resp:
                ret.append(r)
        return ret


    def find_first_match_id(self, response, ID):
        lines = response.split("\r\n")
        for tests in self.requests[ID].get("tests", []):
            found_matches = 0
            tests_m = tests.get("matches", None)
            if tests_m is None:
                continue

            for test in tests_m:
                for line in lines:
                    if line != "" and test.match(line):
                        found_matches += 1
                        break
            if found_matches == len(tests_m):
                grouphits = NmapParser.test2grouphits(lines, tests_m)
                return NmapParser.replace_product_vars(
                    tests.get("product", {}).copy(),
                    grouphits
                )
        return None

    def find_first_match(self, response):
        for i in range(0, len(self.requests)):
            ret = self.find_first_match_id(response, i)
            if ret != {} and ret is not None:
                return ret
        return {}

    def entry_exist(self, method, resource):
        for req in self.requests:
            if req["query"]["method"] == method and req["query"]["resource"] == resource:
                return req["id"]
        return None

    def parse_file(self, nmap_file):
        logger.info("Parsing nmap services file at %s", nmap_file)
        with open(nmap_file, "r") as fprobes:
            lines = fprobes.read().split("\n")

        # Remove all comments
        lines = [x for x in lines if not x.startswith("#")]

        # Remove empty lines
        lines = [x for x in lines if not x == ""]

        # We are only interested in HTTP requests
        lines = self.remove_unused(lines)

        ID = len(self.requests)
        currid = None

        for line in lines:
            if line.startswith("Probe "):
                query = line.split("|")[1]
                http_lines = query.split("\r\n")
                method = http_lines[0].split(" ")[0]
                resource = http_lines[0].split(" ")[1]
                currid = self.entry_exist(method, resource)
                if currid is None:
                    self.requests.append({})
                    self.requests[ID]["id"] = ID

                    self.requests[ID]["query"] = {}
                    self.requests[ID]["query"]["method"] = method
                    self.requests[ID]["query"]["resource"] = resource

                    self.requests[ID]["ports"] = []
                    self.requests[ID]["ranges"] = []
                    self.requests[ID]["tests"] = []
                    currid = ID
                    ID += 1

            elif line.startswith("ports "):
                ports = line[6:].split(",")
                # Split up into ports and ranges for easier searching in the future
                ports2 = [x for x in ports if "-" not in x]
                ranges = [x for x in ports if "-" in x]

                for port in ports2:
                    self.requests[currid]["ports"].append(int(port))
                for port_range in ranges:
                    self.requests[currid]["ranges"].append(port_range)

            elif line.startswith("match "):
                match_dict = NmapParser.match2dict(line)
                if match_dict is not None:
                    self.requests[currid]["tests"].append(match_dict)

        logger.info("Done parsing nmap services file")

    def remove_unused(self, lines):
        prefixes = (
            "Probe TCP GetRequest",
            "Probe TCP HTTPOptions",
            "Probe TCP FourOhFourRequest",
            "Probe TCP docker"
        )
        keep = False
        ret = []
        for line in lines:
            if keep is True:
                if line.startswith("Probe"):
                    keep = False
                else:
                    ret.append(line)
            if keep is False:
                if line.startswith(prefixes):
                    ret.append(line)
                    keep = True
        return ret

    @staticmethod
    def port_in_range(port, port_range):
        """ Check if a port is in the range specified with "x-y" """
        try:
            port = int(port)
            num1, num2 = port_range.split("-")
            num1 = int(num1)
            num2 = int(num2)
        except (ValueError, AttributeError):
            logger.error("Unable to parse port or port range, port: '%s' | range: '%s'",
                          port, port_range)
            return False

        if port >= num1 and port <= num2:
            return True
        return False

    @staticmethod
    def port_in_ranges(port, ranges):
        """ Check if a port is in a list of ranges each specified as "x-y" """
        for port_range in ranges:
            if NmapParser.port_in_range(port, port_range):
                return True
        return False

    @staticmethod
    def match2dict(line):
        ret = {}
        # Find the match string
        match = re.findall(r"m\|[^|]*\|", line)
        if match == []:
            match = re.findall("m%[^%]*%", line)
            if match == []:
                match = re.findall("m=[^=]*=", line)
        match = match[0]
        match = match[2:-1]

        # We don't have control over which HTTP version is used, so we match on either
        # 1.0 or 1.1
        match = match.replace(r"HTTP/1\.0", r"HTTP/1\.[01]")
        match = match.replace(r"HTTP/1\.1", r"HTTP/1\.[01]")

        # Because headers might be rearranged, we need to match each line seperately
        matches_tmp = re.split(r"([^\^]\\r\\n)", match)
        matches = []
        curr_match = 0
        for i in range(0, len(matches_tmp)):
            if matches_tmp[i] == r"\r\n":
                continue
            elif matches_tmp[i].endswith(r"\r\n"):
                matches[curr_match-1] += matches_tmp[i][0]
            else:
                matches.append(matches_tmp[i])
                curr_match += 1
        ret["matches"] = []
        for m in matches:
            # There will be some empty lines when regex is used on the body
            if m == "":
                continue

            # TODO: Some expression cannot be split into separate lines without
            # extra work. These are just removed for now, it's 87 expressions.
            try:
                ins = re.compile(m, re.DOTALL)
            except Exception as e:
                logger.debug("Unable to parse %s | error: %s", line, e)
                return None

            ret["matches"].append(ins)

        # Parse remaining string
        ind = line.find(match) + len(match)
        rem = line[ind:]

        # Get the rest about product info
        rest = re.findall(r"(([a-z]|cpe:)\/[^/]*\/)", rem)
        product = {}
        for r in rest:
            if r[1] == "p":
                product["product"] = r[0][2:-1]
            elif r[1] == "v":
                product["version"] = r[0][2:-1]
            elif r[1] == "i":
                product["info"] = r[0][2:-1]
            elif r[1] == "h":
                product["hostname"] = r[0][2:-1]
            elif r[1] == "o":
                product["operatingsystem"] = r[0][2:-1]
            elif r[1] == "d":
                product["device"] = r[0][2:-1]
            elif r[1] == "cpe:":
                product["cpe"] = r[0][5:-1]

        ret["product"] = product
        return ret


class ServiceDetection:
    def __init__(self):
        self.app = None
        self.nmap = NmapParser()
        self.socket = None
        self.nmap_probes = {}

    def read_config(self):
        response = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/NmapProbes")
        ipc.assert_response_valid(response, dict)
        self.nmap_probes = response["text"].copy()
        for key, value in self.nmap_probes.items():
            self.nmap.add_file(value)

        # Print warning if not found probes

    def add_routes(self):
        self.app.add_route(self.stop, '/exit', methods=["POST"])
        self.app.add_route(self.requests, '/requests/<port:int>', methods=["GET"])
        self.app.add_route(self.match, '/match', methods=["POST"])
        self.app.add_route(self.status, '/status', methods=["GET"])

    def run(self):
        self.socket = ipc.unix_socket(SOCKET_SD)
        self.read_config()
        self.app = Sanic("ServiceDetection")
        self.add_routes()
        logger.info("Initializing module service detection")
        self.app.run(sock=self.socket, access_log=False)

    async def status(self, _request):
        return sanic.response.json(RETURN_UP)

    async def stop(self, _request):
        self.app.stop()
        self.socket.close()
        return sanic.response.json(RETURN_STOPPED)

    async def requests(self, request, port):
        raise ServerError("Not implemented", status_code=500)

    async def match(self, request):
        try:
            data = base64.b64decode(request.body)
            data = data.decode()
        except:
            raise ServerError("Unable to decode HTTP body", status_code=500)

        match = self.nmap.find_matches(data)
        return sanic.response.json(match)
