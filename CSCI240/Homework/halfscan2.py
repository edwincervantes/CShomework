#A SYN scan(half scan) that avoids being logged by creating a full connection.
#The SYN scan is built by calling functions from scapy to do so
#EJ Cervantes April 1, 2019
#Consulted https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref for basics on half/SYN scans

#! /usr/bin/python

import random
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#Declare list and globals
open = list()
ports = list()


#Our main function for syn scan. We need to be returned the valued 0x12 to know that a port is open.
#When we know a port is open we send the RST flag.
def runScan(ip, x1):
 src_port = RandShort()
 synScan = sr1(IP(dst=ip)/ TCP(sport=src_port,dport=x1,flags="S"))
 if(str(type(synScan))=="<type 'NoneType'>"):
  return False
 if(synScan.haslayer(TCP)):
  if(synScan.getlayer(TCP).flags == 0x12):
   send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"))
   open.append(x1)
   return True
 if (synScan.getlayer(TCP).flags == 0x14):
  return False
 else:
  return False

#User input a user decides between two port numbers and a list of all integers between is generated at random
#Then in the order of the list, we scan each of the random ports as to avoid detection
def getUsrInput():

  ip = raw_input("Enter the IP address you wish to scan in the form xx.xxx.xxx.x ")
  x1 = input("What number port do you wish to begin at? ")
  x2 = input("What number port do you wish to end at? ")
  ports = [random.randint(x1,x2) for i in range(x2)]
  for item in ports:
   runScan(ip, item)


getUsrInput()
for item in open:
  print item




###########################
#Part 3.3 essay 
#Having your ports scanned consistently should usually be no sign for worry especially when they connect
#to the socket because there is a log created. If one is trying to defend against a half scan, which
#is much more likely to be used by the bad guys rather than a full scan, you could modify the above code to combat it.
#For everytime someone scanned a port of yours and your server sends back a SYN+ACK, you should expect to be sent back a RST+ACK.
#If you as the server never recieves a RST+ACK in return, you should close that port to the client who scanned it automatically.
###############################

