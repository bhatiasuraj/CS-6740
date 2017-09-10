#!/usr/bin/python

from socket import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-u", help="USERNAME")
parser.add_argument("-sip", help="server-ip")
parser.add_argument("-sp", help="port", type=int)
args = parser.parse_args()


clientSocket = socket(AF_INET, SOCK_DGRAM)
message = 'Hello!'
addr = (args.sip, args.sp)

clientSocket.sendto(message, addr)

data, server = clientSocket.recvfrom(1024)
print(data)

