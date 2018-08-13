#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os.path
import string
import random
import logging

logger = logging.getLogger(__name__)


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


def merge_dicts(a, b, path=None):
    "merges b into a"
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            else:
                raise Exception('Conflict at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a
