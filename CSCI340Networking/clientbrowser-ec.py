#Your job in this exercise is to get the hello world file from your web server.
#You are building a client here.

from socket import *

# fill the missing socket information for IPv4 and TCP
mysock = socket(AF_INET,SOCK_STREAM)

#fill the missing host and port information
mysock.connect(('', 8888))

#fill the missing get request infomation
cmd = 'GET /HelloWorld.html HTTP/1.1\r\n\r\n'.encode()
mysock.send(cmd)

while True:
    data = mysock.recv(1024)
    if (len(data) < 1):
        break
    print(data.decode())
mysock.close()
