#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function

import os
import yaml
import multiprocessing

# Set up logging so that is ready before we start importing modules
import logging
import logging.config
from logging import handlers
if __name__ == '__main__':
    path = 'logging.yaml'
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.load(f.read())
            logging.config.dictConfig(config)

import argparse
import sys

from lib import procs
from lib import constants


def main():
    parser = argparse.ArgumentParser(description='Intrasploit Framework')
    parser.add_argument("--ip", "-i", type=str, help="IP to accept traffic at (web server)",
                        default="0.0.0.0")

    parser.add_argument("--interface", "-I", type=str,
                        help="Interface to use when blocking traffic", default="eth0")

    parser.add_argument("--port", "-p", type=int, help="Port to use for web server", default=80)
    parser.add_argument("--firewall", "-f", type=str,
                        help="Pass a filename if you want to backup iptables", default=None)

    parser.add_argument("--config", "-c", type=str, help="Config file (ini)",
                        default='.config/intrasploit.ini')
    args = vars(parser.parse_args())

    args["config"] = os.path.join(os.path.expanduser("~"), args["config"])

    logger = logging.getLogger("intrasploit")
    logger.info("Started intrasploit")

    # Create directory if it doesn't exist
    if os.path.exists(constants.SOCKET_DIR) is False:
        logger.info("Created directory for sockets")
        os.makedirs(constants.SOCKET_DIR)

    procs2 = procs.start_processes(args["config"])

    logger.info("Reached end of main")
    for proc in procs2:
        proc.join()


if __name__ == '__main__':
    main()
