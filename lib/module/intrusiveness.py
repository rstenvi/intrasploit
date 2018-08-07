#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from enum import Enum

class Intrusiveness(Enum):
    NEVER = 0
    NONE = 1
    HIGH_VOLUME = 2
    BRUTE_FORCE = 3

    # Default is so high that it will never be loaded
    DEFAULT = 99
