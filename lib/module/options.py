#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.


class Options:
    def __init__(self, Global):
        self.options = Global
        self.overridden = {}

    def set_global(self, key, value):
        self.options[key] = value

    def set_local(self, key, value):
        self.overridden[key] = value

    def list_to_js_array(self, plist):
        ret = '['
        for item in plist:
            esc = item.replace(r'"', r'\"')
            ret += '"' + esc + '",'
        ret = ret[:-1] + ']'    # Remove last "," and add ]
        return ret

    def get_dict(self):
        ret = self.overridden.copy()
        for key, value in self.options.items():
            if key not in ret:
                ret[key] = value

        # Transform to proper JS-strings
        # TODO: Not perfect, but good enough
        for key, val in ret.items():
            if isinstance(val, list):
                ret[key] = self.list_to_js_array(val)
        return ret

    def get(self, key):
        if key in self.overridden:
            return self.overridden[key]
        return self.options.get(key, None)


    def __contains__(self, key):
        return (key in self.options) or (key in self.overridden)

    def __setitem__(self, key, value):
        self.set_local(key, value)

    def __getitem__(self, key):
        return self.get(key)
