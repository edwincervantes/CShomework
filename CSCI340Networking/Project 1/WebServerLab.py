########################################################################################################
#
#
#
#
#					Socket Programming
#					Author: EJ Cervantes
#					11 September 2019
#
#
#
########################################################################################################
#import socket module
from socket import *
import sys # In order to terminate the program

#create 2 vars host and port and assign a port number. Use something over 1024
HOST, PORT = '', 8888

#Prepare a sever socket
#create a variable named listen_socket and use the socket lib we just called above to
#(AF_INET is used for IPv4 protocols) and (SOCK_STREAM is used for TCP)
serverSocket = socket(AF_INET,SOCK_STREAM)

#bind the socket to server address and server port
serverSocket.bind((HOST,PORT))

#listen for one connection
serverSocket.listen(1)


while True:
#Establish the connection
    print ("Ready to serve...")
#Creates socket
    #listen for the requests that are coming in from client connection and addrt
    connectionSocket, addr = serverSocket.accept()

    try:
        message = connectionSocket.recv(1024).decode('utf-8')
        filename = message.split()[1]   
        #filename = '/HelloWorld.html'
        f = open(filename[1:])
        outputdata = f.read()
    #Send one HTTP header line into socket   
        connectionSocket.send('\nHTTP/1.x 200 OK\n') #sends a 200 OK header line



    #Send the content of the requested file to the client
        for i in range(0, len(outputdata)):
            connectionSocket.send(outputdata[i].encode())
        connectionSocket.send("\r\n".encode())
    #Closes socket
        connectionSocket.close()
    except IOError as e: 
        connectionSocket.send("HTTP/1.x 404 Not Found\r\n\r\n")
        connectionSocket.send("<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n")

    serverSocket.close()
    sys.exit()#Terminate the program after sending the corresponding data