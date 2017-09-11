#!/usr/bin/python

from socket import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-u", help="USERNAME")
parser.add_argument("-sip", help="server-ip")
parser.add_argument("-sp", help="port", type=int)
args = parser.parse_args()

addr = (args.sip, args.sp)

clientSocket = socket(AF_INET, SOCK_DGRAM)
message = raw_input("+>")
if message == "list":
	clientSocket.sendto("list", addr)
        data, server = clientSocket.recvfrom(1024)
	print ("<-", data)

clientSocket.sendto(message, addr)

