#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module import payload
from lib.module.payload import PayloadClass

class PayloadModule(PayloadClass):
    def __init__(self):
        super().__init__(**{
            'Name': 'Empty Placeholder',
            'Description': "Empty placeholder object",
            'Options': [],
            'payload': {}
        })

    def payload_code(self):
        return ""
