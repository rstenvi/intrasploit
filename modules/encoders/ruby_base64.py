#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import base64

from lib.module import payload
from lib.module.encoder import EncoderClass

class EncoderModule(EncoderClass):
    def __init__(self):
        super().__init__(**{
            'Name': 'Ruby base64 encoder',
            'Description': "Encode payload as base64",
            'payload': {
                'arch': payload.ARCH_RUBY
            }
        })

    def encode(self, data, badchars):
        b64 = base64.b64encode(data.encode()).decode()
        return "eval(%({}).unpack(%(m0)).first)".format(b64)
