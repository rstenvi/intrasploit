#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import logging
from string import Template

import sanic
from sanic import Sanic
from sanic.exceptions import ServerError

from lib import ipc
from lib import misc
from lib.constants import *
from lib.module.options import Options
from lib.module import payload
from lib.module.safety import Safety
from lib.module.intrusiveness import Intrusiveness
from lib.module.payload_object import PayloadObject

logger = logging.getLogger(__name__)


class Modules:
    """
    Load all other attack modules.
    """
    def __init__(self):
        self.modules = {}
        self.cc_global_options = None
        self.payloads_wishlist = [
            payload.TYPE_SHELL
        ]

    def get_options(self, modtype, modid):
        if modtype not in self.modules or modid not in self.modules[modtype]:
            return None
        ret = self.modules[modtype][modid].get_options()
        assert isinstance(ret, list)
        return ret

    def get_value(self, modtype, modid, key):
        if modtype not in self.modules or modid not in self.modules[mopdtype]:
            return None
        return self.modules[modtype][modid].get_values(key)

    def parse_import_modules(self, moddir, nest):
        for modfile in os.listdir(moddir):
            full = os.path.join(moddir, modfile)

            # Will not parse sub-directories
            if os.path.isfile(full) and modfile.endswith(".py") and modfile != '__init__.py':
                imp = modfile[:-len(".py")]
                nest2 = nest + "." + imp

                modtype = ""
                modclass = ""
                if nest.endswith(".exploits"):
                    modtype = "exploits"
                    modclass = "ExploitModule"
                elif nest.endswith(".payloads"):
                    modtype = "payloads"
                    modclass = "PayloadModule"
                elif nest.endswith(".encoders"):
                    modtype = "encoders"
                    modclass = "EncoderModule"

                logger.debug("Attempting to load {} of module type: {}".format(imp, modtype))
                mod = __import__(nest2, fromlist=[modclass])
                cls = getattr(mod, modclass)
                newmod = cls()
                # Load options
                newmod.load(self.cc_global_options)
                logger.debug("Loaded {} of module type: {}".format(imp, modtype))
                self.modules[modtype][imp] = newmod

    def parse_mod_dir(self, moddir, options):
        self.cc_global_options = options.copy()
        modtypes = ["exploits", "encoders", "payloads"]
        for modtype in modtypes:
            if modtype not in self.modules:
                self.modules[modtype] = {}
            self.parse_import_modules(os.path.join(moddir, modtype), "modules." + modtype)

    def get_unique_ports(self):
        """
        Return a list of ports which there exist an exploit for.
        """
        ports = []
        for key, val in self.modules["exploits"].items():
            mod_ports = val.get_ports()
            for port in mod_ports:
                if port not in ports:
                    ports.append(port)
        return ports

    def get_unique_options(self):
        options = []
        for key, val in self.modules["exploits"].items():
            mod_options = val.get_options()
            for option in mod_options:
                if option not in options:
                    options.append(option)
        return option

    def badchar_in_payload(self, payload, badchars):
        for badchar in badchars:
            if badchar in payload:
                return True
        return False

    def find_encoders(self, arch):
        ret = []
        for key, module in self.modules["encoders"].items():
            if module.get_payload_arch() == arch:
                ret.append(module)
        return ret

    def encode_payload(self, payload, badchars, module, arch):
        for key, module in self.modules["encoders"].items():
            if module.get_payload_arch() == arch:
                encoded = module.encode(payload, badchars)

    def find_payload(self, arch):
        for ptype in self.payloads_wishlist:
            for key, module in self.modules["payloads"].items():
                if module.match_payload(ptype, arch):
                    return module
        # No matching payload
        return None

    def find_payloads_ids(self, arch, ptype=payload.TYPE_ANY):
        ret = []
        for key, module in self.modules["payloads"].items():
            if module.match_payload(ptype, arch):
                ret.append(key)
        return ret

    def code_replace_vars(self, code):
        return Nonea

    def get_exploit_by_id(self, modid):
        return self.modules["exploits"].get(modid, None)

    def get_payload_by_id(self, pid):
        return self.modules["payloads"].get(pid, None)

    def init_exploit(self, name, exploit):
        arch = exploit.get_payload_arch()
        if arch != None:
            payload = self.find_payload(arch)
            if payload == None:
                return ""

            pcode = payload.payload_code()
            pobject = PayloadObject

        return ""

    def find_exploits(self, product, slevel, ilevel):
        exploits = []
        for key, val in self.modules["exploits"].items():
            if val.match_classification(slevel, ilevel):
                if val.match_product(product):
                    exploits.append(key)
        return exploits


class ModuleLoader:
    def __init__(self):
        self.modules = Modules()
        self.cc_global_options = None
        self.options = None
        self.app = None
        self.socket = None
        self.config_file = None

    def run(self):
        logger.info("Initializing module loader")
        self.socket = ipc.unix_socket(SOCKET_MODULES)

        # Get global options from config file
        options = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/Options")
        ipc.assert_response_valid(options, dict)
        options = self.parse_option(options["text"])

        # Get options for this class
        mod_options = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/section/Modules")
        ipc.assert_response_valid(mod_options, dict)
        self.options = mod_options["text"].copy()

        # Some values must be present in options
        assert "safety" in self.options
        assert "intrusiveness" in self.options

        # Try and convert string to enums
        try:
            self.options["safety"] = Safety[self.options["safety"]]
            self.options["intrusiveness"] = Intrusiveness[self.options["intrusiveness"]]
        except:
            logger.critical("Safety or intrusiveness values could not be converted to enum")
            return

        self.modules.parse_mod_dir("modules/", options)

        self.app = Sanic("ModuleLoader")
        self.add_routes()
        logger.info("Done initializing module loader")
        self.app.run(sock=self.socket, access_log=False)

    def add_routes(self):
        self.app.add_route(self.stop, "/exit", methods=["POST"])
        self.app.add_route(self.status, "/status", methods=["GET"])
        self.app.add_route(self.ports_list, "/ports/list", methods=["GET"])
        self.app.add_route(self.search_exploits_product, "/search/exploits/product", methods=["GET"])
        self.app.add_route(self.exploit_code, "/exploit/code/<modid>", methods=["GET"])
        self.app.add_route(self.exploit_code_payload, "/exploit/code/<modid>/<payid>", methods=["GET"])
        self.app.add_route(self.find_payloads, "/exploit/payloads/<modid>", methods=["GET"])
        self.app.add_route(
            self.exploit_payload_options,
            "/exploit/payload/options/<exploitid>/<payloadid>",
            methods=["GET"]
        )
        self.app.add_route(self.module_finished, "/module/finished/<clientid>/<modid>", methods=["POST"])

    def parse_option(self, options):
        for key, val in options.items():
            if key.startswith("LIST"):
                res = misc.file2list(val, "# ")
                assert res is not None
                options[key] = res
        return options

    def substitute_options(self, data, options):
        tmpl = Template(data)
        try:
            ret = tmpl.substitute(options)
        except Exception as e:
            logger.warning("Unable to substitute variables: {}".format(e))
            raise ServerError("The necessary options were not specified")
        return ret

    def get_payloads(self, modid):
        exploitmod = self.modules.get_exploit_by_id(modid)
        if exploitmod is None:
            return None

        # Find and appropriate payload object, if ARCH is none, we don't need a payload object
        arch = exploitmod.get_payload_arch()
        pobject = None
        if arch != None and arch is not payload.ARCH_NONE:
            payloadmods = self.modules.find_payloads_ids(arch)
            return payloadmods

        # Payload is not necessary
        return ["empty"]

    async def module_finished(self, _request, clientid, modid):
        # Check if we need to redo service detection
        redo = self.modules.get_value("exploits", modid, "RedoServiceDetection")
        if redo == True:
            logger.debug("Redoing service detection on {}".format(clientid))
            jscode = "DNSRebind.exploitStart(null);"
            response = await ipc.async_http_raw(
                "POST",
                SOCK_DATABASE,
                "/append/body/{}/exploit_queue".format(clientid),
                jscode
            )
        return sanic.response.json(RETURN_OK)

    async def exploit_payload_options(self, _request, exploitid, payloadid):
        eret = self.modules.get_options("exploits", exploitid)
        pret = self.modules.get_options("payloads", payloadid)

        # Might have overlapping options, so we return a unique list
        return sanic.response.json(list(set(eret+pret)))

    async def ports_list(self, _request):
        ports = self.modules.get_unique_ports()
        return sanic.response.json(ports)

    async def status(self, _request):
        return sanic.response.json({"status": "up"})

    async def stop(self, _request):
        self.app.stop()
        return sanic.response.json({"status": "stopped"})

    async def search_exploits_product(self, request):
        product = request.raw_args
        exploits = self.modules.find_exploits(
            product,
            self.options["safety"],
            self.options["intrusiveness"]
        )
        return sanic.response.json(exploits)

    async def find_payloads(self, _request, modid):
        resp = self.get_payloads(modid)
        if resp is None:
            return sanic.response.json(RETURN_ERROR)

        return sanic.response.json(resp)

    # TODO: Lot of duplicate code in this and next function
    async def exploit_code_payload(self, request, modid, payid):
        args = request.raw_args
        exploitmod = self.modules.get_exploit_by_id(modid)
        if exploitmod is None:
            return sanic.response.json({"status": "Not found"})

        arch = exploitmod.get_payload_arch()
        payloadmod = self.modules.get_payload_by_id(payid)
        payload_code = payloadmod.payload_code()
        assert payload_code != None

        options = payloadmod.get_options_dict()
        for key, val in args.items():
            options[key] = val
        payload_code = self.substitute_options(payload_code, options)

        encoders = self.modules.find_encoders(arch)
        badchars = exploitmod.get_badchars()
        pobject = PayloadObject(payload_code, encoders, badchars)

        exploit_code = exploitmod.exploit_code(pobject)
        options = exploitmod.get_options_dict()
        for key, val in args.items():
            options[key] = val
        options["MODID"] = modid
        exploit_code = self.substitute_options(exploit_code, options)

        return sanic.response.raw(exploit_code.encode())

    async def exploit_code(self, request, modid):
        args = request.raw_args
        exploitmod = self.modules.get_exploit_by_id(modid)
        if exploitmod is None:
            return sanic.response.json({"status": "Not found"})
        # Find and appropriate payload object, if ARCH is none, we don't need a payload object
        arch = exploitmod.get_payload_arch()
        pobject = None
        if arch != None and arch is not payload.ARCH_NONE:
            payloadmod = self.modules.find_payload(arch)
            payload_code = payloadmod.payload_code()
            assert payload_code != None

            options = payloadmod.get_options_dict()
            for key, val in args.items():
                options[key] = val
            payload_code = self.substitute_options(payload_code, options)

            encoders = self.modules.find_encoders(arch)
            badchars = exploitmod.get_badchars()
            pobject = PayloadObject(payload_code, encoders, badchars)
        else:
            # Use an empty payload object
            pobject = PayloadObject("", None, None)

        exploit_code = exploitmod.exploit_code(pobject)
        options = exploitmod.get_options_dict()
        for key, val in args.items():
            options[key] = val
        options["MODID"] = modid
        exploit_code = self.substitute_options(exploit_code, options)

        return sanic.response.raw(exploit_code.encode())
