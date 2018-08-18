#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function

import os
import sys
import base64

from argparse import ArgumentParser
from pprint import pprint


from lib.constants import *
from lib import ipc
from lib import procs


cli = ArgumentParser()
cli.add_argument("--version", "-v", help="Display version", action="store_true")
subparsers = cli.add_subparsers(dest="subcommand")

http_socks = {
    "config": SOCK_CONFIG,
    "database": SOCK_DATABASE,
    "modules": SOCK_MODULES,
    "webserver": SOCK_WEBSERVER,
    "dns": SOCK_DNS,
    "service_detection": SOCK_SD
}

def get_value(section, key):
    resp = ipc.sync_http_raw("GET", SOCK_CONFIG, "/get/variable/{}/{}".format(section, key))
    if ipc.response_valid(resp, dict):
        return resp["text"].get(key, None)
    return None

def argument(*name_or_flags, **kwargs):
    """Convenience function to properly format arguments to pass to the
    subcommand decorator.

    """
    return ([*name_or_flags], kwargs)


def subcommand(args=[], parent=subparsers):
    """Decorator to define a new subcommand in a sanity-preserving way.
    The function will be stored in the ``func`` variable when the parser
    parses arguments so that it can be called directly like so::

        args = cli.parse_args()
        args.func(args)

    Usage example::

        @subcommand([argument("-d", help="Enable debug mode", action="store_true")])
        def subcommand(args):
            print(args)

    Then on the command line::

        $ python cli.py subcommand -d

    """
    def decorator(func):
        parser = parent.add_parser(func.__name__, description=func.__doc__)
        for arg in args:
            parser.add_argument(*arg[0], **arg[1])
        parser.set_defaults(func=func)
    return decorator

@subcommand()
def purge(args):
    print("Purging database")
    resp = ipc.sync_http_raw("POST", http_socks["database"], "/purge")
    if ipc.response_valid(resp, dict):
        print("Result {}".format(resp["text"]))

@subcommand()
def modules(args):
    resp = ipc.sync_http_raw("GET", http_socks["modules"], "/modules/loaded")
    if ipc.response_valid(resp, dict):
        for key, val in resp["text"].items():
            print("{}:".format(key))
            for v in val:
                print("\t{}".format(v))
    else:
        print("error")
        print(resp)

@subcommand()
def clients(args):
    resp = ipc.sync_http_raw("GET", http_socks["database"], "/get/clients")
    ids = resp["text"]
    if ipc.response_valid(resp, dict):
        for key, val in ids.items():
            print("{} ({} - {})".format(key, val.get("publicip", None), val["browser"]))
            for child in val["childs"]:
                print("\t{} ({}:{})".format(child["id"], child["ip"],
                                                   child["port"]))

def stop_all():
    port = get_value("Options", "LPORT")
    if port == None:
        print("Unable to get port of shell")
    try:
        port = int(port)
    except:
        print("Unable to convert port {} to int".format(port))
        sys.exit(1)
    print("Stopping shell at port {}".format(port))
    procs.stop_shell(port)

    for key, val in http_socks.items():
        print("Stopping {}".format(key))
        _res = ipc.sync_http_raw("POST", val, "/exit")

@subcommand([argument("service", help="Stop a service")])
def stop(args):
    service = args.service
    if service == "all":
        stop_all()
    elif service in http_socks:
        _res = ipc.sync_http_raw("POST", http_socks[service], "/exit")
    else:
        print("Invalid service {}".format(service))

@subcommand([argument("port", help="Start a webserver")])
def start_webserver(args):
    port = int(args.port)
    res = ipc.sync_http_raw("POST", http_socks["webserver"], "/start/{}".format(port))
    print(res["text"])


@subcommand()
def reload(args):
    resp = ipc.sync_http_raw("POST", http_socks["modules"], "/reload")
    if ipc.response_valid(resp, dict):
        print("Status: {}".format(resp["text"].get("status", "Unknown")))
    else:
        print("Error")
        print(resp)

@subcommand()
def status(args):
    for key, val in http_socks.items():
        try:
            resp = ipc.sync_http_raw("GET", val, "/status")
        except:
            print("{} is unavailable".format(key))
            continue
        if ipc.response_valid(resp, dict):
            print("Status for {} - {}".format(key, resp["text"].get("status")))
        else:
            print("Received an invalid response {}".format(resp))

def dump_client(client):
    if "father" in client and client["father"] == True:
        print("Client: {} - ({})".format(client.get("id", "unknown"), client.get("ip", "unknown")))
    else:
        print("Client: {} - (Parent: {} - {}:{})".format(
            client.get("id", ""), client.get("parent"), client.get("ip", ""), client.get("port", "")
        ))
        print("Products")
        for p in client.get("product", []):
            print("\t{} (Info: {} CPE: {})".format(p["product"], p.get("info"), p.get("cpe")))
        print("Matched modules")
        for m in client.get("matched_modules", []):
            print("\t{}".format(m))
        print("Queued exploits")
        for q in client.get("exploit_queue", []):
            print("\t{}".format(q))

        print("HTTP response\n")
        http = client.get("httpresponse")
        byte_str = base64.b64decode(http)
        print(byte_str.decode())


@subcommand([argument("client", help="Dump information about client")])
def dump(args):
    client = args.client
    resp = ipc.sync_http_raw("GET", http_socks["database"], "/get/client/{}".format(client))
    if ipc.response_valid(resp, dict):
        dump_client(resp["text"])
    else:
        print("Unable to find information about client {}".format(client))

if __name__ == "__main__":
    args = cli.parse_args()
    if args.subcommand is None:
        if args.version == True:
            print("Version 0.0.1")
        else:
            cli.print_help()
    else:
        args.func(args)
