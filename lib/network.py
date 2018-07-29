#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import socket
import sys

try:
    from netaddr import IPAddress, IPNetwork
except ImportError:
    print("error importing netaddr, install with 'pip3 install netaddr'")
    sys.exit(1)


def create_socket(ip_addr, port):
    assert isinstance(port, int)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (ip_addr, port)
    sock.bind(server_address)
    return sock


def validIPv4(ip_addr):
    parts = ip_addr.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            int(part)
        except ValueError:
            return False
    return True


def internal_ip(ip_addr):
    try:
        i = IPAddress(ip_addr)
    except:
        return False

    return i in IPNetwork("192.168.0.0/16") \
        or i in IPNetwork("172.16.0.0/12") \
        or i in IPNetwork("10.0.0.0/8") \
        or i in IPNetwork("127.0.0.1/8")
