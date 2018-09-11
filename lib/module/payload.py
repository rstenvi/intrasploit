#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module.base import ModuleBaseClass

TYPE_NONE = 0
TYPE_SHELL = 1
TYPE_ANY = 99

ARCH_NONE = 0
ARCH_RUBY = 1
ARCH_LINUX_X86 = 2

class PayloadClass(ModuleBaseClass):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def payload_code(self, options):
        return None

