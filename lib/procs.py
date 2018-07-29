#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import time
import sys
import logging

import multiprocessing
from multiprocessing import Process

from services.config import Config
from services.service_detection import ServiceDetection
from services.dns import DNSAPI
from services.webserver import ManageWebservers
from services.import_modules import ModuleLoader
from services.database import Database
from services.rshell import ShellReceiver

from lib import ipc
from lib.constants import *
from lib.shell import Shell

logger = logging.getLogger(__name__)


def wait_service_up(url, attempts=10, delay=0.5):
    """
    Keep running until service is up or service has failed to start.
    """
    for _i in range(0, attempts):
        try:
            resp = ipc.sync_http_raw("GET", url, "/status")
            if resp["text"]["status"] == "up":
                return True
        except:
            logger.debug("Service URL: {} was not detected as up".format(url))
            pass
        time.sleep(delay)
    return False

def stop_services(stoplist):
    for url in stoplist:
        logger.info("Stopping service with URL: {}".format(url))
        ipc.sync_http_raw("POST", url, "/exit")

def stop_shell(port):
    logger.info("Stopping shell at port: {}".format(port))
    shell = Shell("127.0.0.1", port)
    shell.exit()

def start_processes(config_ini):
    procs = []
    stoplist = []

    logger.info("Starting config service")
    conf = Config()
    proc = Process(target=conf.run, args=(config_ini,))
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_CONFIG) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_CONFIG)

    logger.info("Starting service-detection service")
    service_detection = ServiceDetection()
    proc = Process(target=service_detection.run, args=())
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_SD) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_SD)

    logger.info("Starting DNS service")
    dns = DNSAPI()
    proc = Process(target=dns.run, args=())
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_DNS) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_DNS)

    logger.info("Starting web-server service")
    mgmt_server = ManageWebservers()
    proc = Process(target=mgmt_server.run, args=())
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_WEBSERVER) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_WEBSERVER)

    logger.info("Starting module-loader service")
    module_ldr = ModuleLoader()
    proc = Process(target=module_ldr.run, args=())
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_MODULES) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_MODULES)

    logger.info("Starting database service")
    database = Database()
    proc = Process(target=database.run, args=())
    procs.append(proc)
    proc.start()

    if wait_service_up(SOCK_DATABASE) is False:
        stop_services(stoplist)
        sys.exit(1)
    stoplist.append(SOCK_DATABASE)

    logger.info("Starting shell-receiver service")
    shell = ShellReceiver()
    proc = Process(target=shell.run, args=())
    procs.append(proc)
    proc.start()

    # No need to wait for shell-service to be up
    logger.info("All processes have started")
    return procs
