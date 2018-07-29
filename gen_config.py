#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from __future__ import print_function

import os
import sys
import argparse
import sys
import json
from string import Template

def main():
    parser = argparse.ArgumentParser(description='Generate config for intrasploit')
    parser.add_argument("--root", "-r", type=str,
                        help="Root domain",
                        required=True
                        )
    parser.add_argument("--publicip", "-p", type=str,
                        help="Public IP address of the server",
                        required=True
                        )
    parser.add_argument("--template", "-t", type=str,
                        help="Template to use",
                        default="config.tmpl"
                        )
    parser.add_argument("--json", "-j", type=str,
                        help="Additional json to use in template",
                        default="{}"
                        )
    args = vars(parser.parse_args())

    try:
        json_config = json.loads(args["json"])
    except Exception as e:
        print("ERROR: Unable to parse json: {}, error: {}".format(args["json"], e))
        sys.exit(1)

    # Used for parameter substitution
    params = {**args, **json_config}

    with open(args["template"], "r") as tmpl_file:
        template = tmpl_file.read()

    template = Template(template)
    try:
        output = template.substitute(params)
    except KeyError as key:
        print("ERROR: Key '{}' was found in template, but not config".format(key))
        sys.exit(1)

    confdir = os.path.join(os.path.expanduser("~"), ".config")
    if not os.path.exists(confdir):
        os.makedirs(confdir)

    outlocation = os.path.join(confdir, "intrasploit.ini")
    with open(outlocation, "w") as out_file:
        out_file.write(output)

    print("Wrote config file to {}".format(outlocation))

if __name__ == '__main__':
    main()
