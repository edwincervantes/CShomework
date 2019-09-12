#full connection in python
# Gary Lewandowski
from socket import *

open = list()
x1 = 0
x2 = 0

def connectTo(host, port):
  global x1
  serverName = host
  serverPort = port
  clientSocket = socket(AF_INET,SOCK_STREAM)
  clientSocket.settimeout(1)
  try:
    clientSocket.connect((serverName,serverPort))
    clientSocket.close()
    open.append(x1)
    return True
  except Exception as e:
    # didn't connect
    clientSocket.close()
    return False

def setIPandRange():
  global x1
  global x2
  ip = raw_input("Enter the IP address you wish to scan in to form xx.xxx.xxx.x ")
  x1 = input("What number port do you wish to begin at? ")
  x2 = input("What number port do you wish to end at? ")
  while x1 < x2:
   connectTo(ip, x1)
   x1 += 1

setIPandRange()
print("The following ports are open:")
for item in open:
  print item
