#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module.options import Options
from lib.module import payload

class ModuleBaseClass:
    def __init__(self, **kwargs):
        self.info = kwargs

        self.options = None

        self.known_defaults = {
            "RedoServiceDetection": False
        }

    def load(self, options):
        self.options = Options(options)

    def get_options_dict(self):
        return self.options.get_dict()

    def dump(self):
        return self.info

    def get_value(self, key, default=None):
        # Return value if specified, otherwise return default or None if nothing is specified
        return self.info.get(key, self.known_defaults.get(key, default))

    def get_name(self):
        return self.info.get("Name", "Name not set")

    def match_name(self, search):
        return self.info.get("Name", "").lower().find(search.lower()) >= 0

    def get_options(self):
        return self.info.get("Options", [])

    def match_payload(self, ptype, parch):
        pload = self.info.get("payload", {})
        return (ptype == payload.TYPE_ANY or pload.get("type", None) == ptype) and pload.get("arch", None) == parch

    def get_paylod_type(self):
        return self.info.get("payload", {}).get("type", None)

    def get_payload_arch(self):
        return self.info.get("payload", {}).get("arch", None)
