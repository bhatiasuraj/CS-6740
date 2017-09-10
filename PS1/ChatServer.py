#!/usr/bin/python

from socket import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-sp", help="port", type=int)
args = parser.parse_args()
print(args.sp)

serverSocket = socket(AF_INET, SOCK_DGRAM)

serverSocket.bind(('', args.sp))

while True:
	message, address = serverSocket.recvfrom(1024)
	serverSocket.sendto(message, address)


