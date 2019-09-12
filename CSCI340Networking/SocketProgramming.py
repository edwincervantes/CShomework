###########################################################################################################################################################################################
#
#
#
#                                                           CSCI 340: Networking - Socket Programming(in class)
#
#
#
############################################################################################################################################################################################

#After getting this to compile and run successfully. Navigate to your host address:port# http://127.0.0.1:8888/

#import socket mod
import socket

#create 2 vars host and port and assign a port number. Use something over 1024
HOST, PORT = '', 8888

#create a TCP socket server

#prepare a server socket
#create a variable named listen_socket and use the socket lib we just called above to
#(AF_INET is used for IPv4 protocols) and (SOCK_STREAM is used for TCP)
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind the socket to server address and server port
listen_socket.bind((HOST,PORT))

#listen for one connection
listen_socket.listen(1)

#print the message on the server so we can see it's listening on port 8888
print ("My CSCI340 server is listening on %s" % PORT)

#to keep the program running use while statement! endless loop
while True:
    #listen for the requests that are coming in from client connection and addrt
    client_connection, client_address = listen_socket.accept()

    #accept only specified bytes of data
    request = client_connection.recv(1024).encode('utf-8')

    #print out the request
    print(request)

    #create a message that we can send to the client browser and assign it to http_response var
    http_response = ("Hello CSCI 340. This is my first custom server")

    #Format the data before send it the client, take the string response above and turn into byte mode
    client_connection.sendall(bytes(http_response.encode('utf-8')))

    #make sure to close the connection when it's completed so we dont use all of the resources
    client_connection.close()