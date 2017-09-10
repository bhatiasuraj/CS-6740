#!/usr/bin/python

from socket import *
import argparse

serverSocket = socket(AF_INET, SOCK_DGRAM)

serverSocket.bind(('', 12000))

while True:
	message, address = serverSocket.recvfrom(1024)
	serverSocket.sendto(message, address)


