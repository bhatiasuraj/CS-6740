#!/usr/bin/python

from socket import *

clientSocket = socket(AF_INET, SOCK_DGRAM)
message = 'Hello!'
addr = ("127.0.0.1", 12000)

clientSocket.sendto(message, addr)

data, server = clientSocket.recvfrom(1024)
print(data)

