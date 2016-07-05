import socket
import re
import sys
import errno
from threading import *

screen_lock = Semaphore(value=1)

def portscan(hostname, portnumber):
	sn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	result = sn.connect_ex((hostname,portnumber))
	if result == 0:
		screen_lock.acquire()
		print (("\t%d \topen") %(portnumber))
		sn.close()
		screen_lock.release()
	else:
		screen_lock.acquire()
		print (("\t%d \tclosed") % (portnumber))
		screen_lock.release()
	return

def checkiforfqdn(hostname, portnumber):
	hn = hostname
	portlist = portnumber.split(',')
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ipchk = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
	chk = ipchk.match(hn)
	print ("\n\n--------------------------------------------------------------------------------")
	print ("\n\t\t\t Scanning:  " + hn.upper())
	print ("--------------------------------------------------------------------------------")
	if not chk:
		try:
			s = socket.gethostbyname(hn)
			c = 0
			for c in range(len(portlist)):
				pl = int(portlist[c])
				t = Thread(target=portscan, args=(hn, pl))
				t.start()
				c = c + 1
		except socket.gaierror: 
				print ("\nCould not resolve the hostname " + hn.upper() + " please check the hostname")
	else:
		c = 0
		for c in range(len(portlist)):
			pl = int(portlist[c])
			t = Thread(target=portscan, args=(hn, pl))
			t.start()
			c = c + 1
	
	return

def main():
	ac = len(sys.argv)
	if ac == 3:
		checkiforfqdn(sys.argv[1], sys.argv[2])
	else:
		print ("\n\n--------------------------------------------------------------------------------")
		print ("\n\t Usage: portscan.py <hostname or IP> <comma separated list of TCP Ports>")
		print ("\t for example: portscan.py 1.1.1.1 1,2,3,4")
	return

main()
