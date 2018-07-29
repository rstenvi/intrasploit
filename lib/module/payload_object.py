#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging

logger = logging.getLogger(__name__)

class PayloadObject:
    def __init__(self, raw, encoders, badchars):
        self.raw = raw
        self.encoders = encoders
        self.badchars = badchars

    def contains_badchars(self, badchars, data):
        for badchar in badchars:
            if badchar in data:
                return True
        return False

    def encoded(self):
        if self.contains_badchars(self.badchars, self.raw) is False:
            return self.raw

        for encoder in self.encoders:
            try:
                data = encoder.encode(self.raw, self.badchars)
            except:
                logger.warning("Unable to encode data with module: {}".format(encoder))
            if self.contains_badchars(self.badchars, data) is False:
                return data

        raise "Unable to encode payload"
