#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Module used to define constants shared across the application.
"""

import os

SOCKET_DIR = "/var/run/intrasploit/"

SOCKET_CONFIG = os.path.join(SOCKET_DIR, "config.sock")
SOCKET_MODULES = os.path.join(SOCKET_DIR, "modules.sock")
SOCKET_SD = os.path.join(SOCKET_DIR, "sd.sock")
SOCKET_WEBSERVER = os.path.join(SOCKET_DIR, "webserver.sock")
SOCKET_DNS = os.path.join(SOCKET_DIR, "dns.sock")
SOCKET_RSHELL = os.path.join(SOCKET_DIR, "shell.sock")
SOCKET_DATABASE = os.path.join(SOCKET_DIR, "database.sock")

SOCK_CONFIG = "http+unix://" + SOCKET_CONFIG
SOCK_MODULES = "http+unix://" + SOCKET_MODULES
SOCK_SD = "http+unix://" + SOCKET_SD
SOCK_WEBSERVER = "http+unix://" + SOCKET_WEBSERVER
SOCK_DNS = "http+unix://" + SOCKET_DNS
SOCK_RSHELL = "http+unix://" + SOCKET_RSHELL
SOCK_DATABASE = "http+unix://" + SOCKET_DATABASE

RETURN_OK = {"status": "ok"}
RETURN_ERROR = {"status": "error"}
RETURN_STOPPED = {"status": "stopped"}
RETURN_UP = {"status": "up"}

# DELETE: IPTABLES_FORMAT.format("-D INPUT", "8.8.8.8", "eth0", "8080")
# INSERT: IPTABLES_FORMAT.format("-I INPUT 1", "8.8.8.8", "eth0", "8080")
IPTABLES_INSERT = "iptables {} -s {} -i {} -p tcp --destination-port {} -j DROP"
IPTABLES_FLUSH = "iptables -F INPUT"
