#!/usr/bin/env python

from __future__ import print_function
from capstone import *
from capstone.mips import *

f=open('./data.bin')

arch=CS_ARCH_MIPS
mode=CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN
code=f.read()
comment="MIPS-32 (little-endian)"

print("platform:"+comment)
print("disasm:")


try:
    md=Cs(arch,mode)
    md.detial=True
    for insn in md.disasm(code,0):
        print("0x%x: \t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

except CsError as e:
    print("ERROR: %s" % e)


