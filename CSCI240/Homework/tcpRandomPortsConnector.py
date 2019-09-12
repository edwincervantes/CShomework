 #Start up a bunch of servers listening on ports
 #Gary Lewandowski
 # 21 March 2019
 # example usage: python tcpRandomPortsConnector.py 
from socket import *
import sys
import threading
import random

class MyThread(threading.Thread):
    def __init__(self, port):
        super(MyThread, self).__init__()
        self.port = port
        self.name = "Thread-{}".format(port)
    def run(self):
		print("{} started!\n".format(self.getName()))
		serverPort = self.port
		serverSocket = socket(AF_INET, SOCK_STREAM)
		serverSocket.bind(('',serverPort))
		serverSocket.listen(1)
		while 1:
			connectionSocket,addr = serverSocket.accept()
			#sentence = connectionSocket.recv(1024)
			print "got connection "
			#capitalizedSentence = sentence.upper()
			#connectionSocket.send(capitalizedSentence)
			connectionSocket.close()
		print("{} finished! \n".format(self.getName()))

def main():
	ports = range(1,10000)
	random.shuffle(ports)
        print ports[:2]
	if len(sys.argv) < 2:
		print("Usage: {} <num ports to listen at>".format(sys.argv[0]))
		return
	limit = int(sys.argv[1])
        print limit
        ports = ports[:limit]
	count = 0
	for x in ports:
		mythread = MyThread(x)
		mythread.start()
        print("Opened: {}\n".format(ports))

if __name__ == '__main__':main()
