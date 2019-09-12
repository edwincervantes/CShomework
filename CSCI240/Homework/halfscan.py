#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
from datetime import datetime
from time import strftime

try:
	target = raw_input("Enter IP Address: ")
	min_port = raw_input("Min port number: ")
	max_port = raw_input("Max port number: ")
	try:
		if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port):
			pass
		else:
			print "Invalid Range or ports"
			sys.exit(1)
	except Exception:
		print "Invalid Range or ports"
		sys.exit(1)
except KeyboardInterrupt:
	print "User requested shutdown. "
	sys.exit(1)

ports = range(int(min_port), int(max_port)+1)
start_clock = datetime.now()
SYNACK = 0x12
RSRACK = 0x14

def checkhost(ip):
	conf.verb=0
	try:
		ping = sr1(IP(dst=ip)/ICMP())
		print "Target is beginning scan"
	except Exception:
		print "Target could not be resolved"
		sys.exit(1)

def scanport(port):
	srcport = RandShort()
	conf.verb=0
	SYNACkpkt=sr1(IP(dst=target)/TCP(sport=srcport,dport=port,flags="S"))
	pktflags = SYNACKpkt.getlayer(TCP).flags
	if pktflags == SYNACK:
		return True
	else:
		return Flase
	RSTpkt = IP(dst=target)/TCP(sport=srcport,dport=port,flags="R")
	send(RSTpkt)

checkhost(target)
print "Scan started at " + strftime("%H:%M:%S")

for port in ports:
	status = scanport(port)
	if status ==True:
		print "Port " + str(port) + ":Open"
stop_clock = datetime.now()
totaltime = stop_clock - start_clock
print "Scan finished"
print "Durantion: " +str(total_time)
