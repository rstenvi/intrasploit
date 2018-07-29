#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module.base import ModuleBaseClass

class EncoderClass(ModuleBaseClass):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def encode(self, data, badchars):
        pass
