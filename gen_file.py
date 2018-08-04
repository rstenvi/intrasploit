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
    parser.add_argument("--template", "-t", type=str,
                        help="Template to use",
                        default="config.tmpl"
                        )
    parser.add_argument("--json", "-j", type=str,
                        help="Additional json to use in template",
                        default="{}"
                        )
    parser.add_argument("--output", "-u", type=str,
                        help="Output file",
                        default="~/.config/intrasploit.ini"
                        )
    args = vars(parser.parse_args())

    try:
        params = json.loads(args["json"])
    except Exception as e:
        print("ERROR: Unable to parse json: {}, error: {}".format(args["json"], e))
        sys.exit(1)

    with open(args["template"], "r") as tmpl_file:
        template = tmpl_file.read()

    template = Template(template)
    try:
        output = template.substitute(params)
    except KeyError as key:
        print("ERROR: Key '{}' was found in template, but not json".format(key))
        sys.exit(1)

    oname = args["output"]
    if oname.startswith("~"):
        oname = os.path.join(os.path.expanduser("~"), oname[2:])

    dirname = os.path.dirname(oname)
    if not os.path.exists(dirname):
        os.makedirs(dirname)


    with open(oname, "w") as out_file:
        out_file.write(output)

    print("Wrote file to {}".format(args["output"]))

if __name__ == '__main__':
    main()
