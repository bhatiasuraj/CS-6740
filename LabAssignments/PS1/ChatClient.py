#!/usr/bin/python

from socket import *
import argparse
import sys

def sendToServer(message, socket, username, addr):
	if message == "SIGN-IN":
		socket.sendto("SIGN-IN", addr)
		socket.sendto(username, addr)		

	if message.split()[0] == "send":
		socket.sendto(message, addr)

	if message == "list":
		socket.sendto("list", addr)
		data, server = socket.recvfrom(1024)
		print str("<-"+data)

def argsParser():

        parser = argparse.ArgumentParser()

        parser.add_argument("-u", help="USERNAME")
        parser.add_argument("-sip", help="server-ip")
        parser.add_argument("-sp", help="port", type=int)
	args = parser.parse_args()

	return args.u, args.sp, args.sip

def main():

	username, port, ip = argsParser()
	addr = (ip, port)
	clientSocket = socket(AF_INET, SOCK_DGRAM)
        sendToServer("SIGN-IN", clientSocket, username, addr)
	while True:
	        message = raw_input("+>")
	        if message == "list":
			sendToServer(message, clientSocket, username, addr)
		if message.split()[0] == "send":
			sendToServer(message, clientSocket, username, addr)
		if message == "exit":
			clientSocket.close()
			sys.exit(0)

if __name__ == "__main__":
    main()

