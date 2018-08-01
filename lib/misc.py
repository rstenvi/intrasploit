#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os.path
import string
import random


def random_id(size=16, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def hostname2id(hostname):
    ind = hostname.find(".")
    return hostname[:ind]

def file2list(fname, ignore="# "):
    if os.path.isfile(fname) is False:
        return None

    with open(fname, "r") as f:
        data = f.read().splitlines()
    ret = []
    for line in data:
        if line.startswith(ignore) is False:
            ret.append(line)
    return ret
