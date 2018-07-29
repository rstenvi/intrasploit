#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from enum import Enum

class Safety(Enum):
    SAFE = 1
    LIKELY_SAFE = 2
    UNSAFE = 3
    DOS = 4

    # Default is so high, that it will never be loaded
    DEFAULT = 99
