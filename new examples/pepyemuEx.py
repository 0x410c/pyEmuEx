#!/usr/bin/env python

import os, sys

sys.path.append("..")
sys.path.append("../lib")

import pefile
from PyEmu import PEPyEmu

def usage():
    print "PEPyEmu"
    print "%s <executable name> <address>" % sys.argv[0]

if len(sys.argv) < 2:
    usage()
    
    sys.exit(1)

exename = sys.argv[1]
address = int(sys.argv[2], 16)

if exename:
    pe = pefile.PE(exename)
else:
    print "[!] Blank filename specified"
    
    sys.exit(2)

imagebase = pe.OPTIONAL_HEADER.ImageBase
codebase = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfCode
database = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.BaseOfData
entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint

print "[*] Image Base Addr:  0x%08x" % (imagebase)
print "[*] Code Base Addr:   0x%08x" % (codebase)
print "[*] Data Base Addr:   0x%08x" % (database)
print "[*] Entry Point Addr: 0x%08x\n" % (entrypoint)

for section in pe.sections:
    if section.Name.startswith(".text"):
        textsection = section
    elif section.Name.startswith(".data"):
        datasection = section
    elif section.Name.startswith(".rdata"):
        rdatasection = section

emu = PEPyEmu()

print "[*] Loading text section bytes into memory"
        
for x in range(len(textsection.data)):
    c = textsection.data[x]
    
    emu.set_memory(codebase + x, int(ord(c)), size=1)

print "[*] Text section loaded into memory"
print "[*] RData Section loading in memory"
for x in range(len(rdatasection.data)):
    c = rdatasection.data[x]
    print "0x%08x"%(database + x)
    emu.set_memory(database + x, int(ord(c)), size=1)
print "[*] RData Loaded in memory"
print "[*] Loading data section bytes into memory"
database = 0x40d000
print len(datasection.data)
for y in range(len(datasection.data)):
    c = datasection.data[y]
    #print "0x%08x"%(database + x + y)
    if int(ord(c)) == 0xbb:
        print "#################0x%08x"%(database+x+y)
    emu.set_memory(database + y, int(ord(c)), size=1)

print "[*] Data section loaded into memory\n"
print "%08x"%emu.get_register("EIP")
print "%08x"%address
emu.set_register("EIP", address)
print "%08x"%emu.get_register("EIP")

#emu.set_stack_variable(0x10, 0x00000000, name="var_10")
#emu.set_stack_variable(0x0c, 0x11111111, name="var_c")
#emu.set_stack_variable(0x08, 0x22222222, name="var_8")
#emu.set_stack_variable(0x04, 0x33333333, name="var_4")

emu.set_stack_argument(0x8, 0x10, name="arg_0")
emu.set_stack_argument(0xc, 0x20, name="arg_4")

c = None
while c != "x":
    if not emu.execute():
        sys.exit(-1)
        
    emu.dump_regs()
    
    c = raw_input("emulator> ")