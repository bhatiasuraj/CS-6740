#!/usr/bin/python

from socket import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-sp", help="port", type=int)
args = parser.parse_args()

serverSocket = socket(AF_INET, SOCK_DGRAM)

serverSocket.bind(('', args.sp))
print("Server Initialized...")

while True:
	message, address = serverSocket.recvfrom(1024)
	if message == "list":
		serverSocket.sendto("Signed in Users: ", address)


