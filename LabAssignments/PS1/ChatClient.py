#!/usr/bin/python

from socket import *
import argparse

def userSignIn(username, addr, s):

	s.sendto("SIGN-IN", addr)
	s.sendto(username, addr)


def createSocket():

        clientSocket = socket(AF_INET, SOCK_DGRAM)
	return clientSocket

def userList(addr, s):

	s.sendto("list", addr)
	data, server = s.recvfrom(1024)
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
	s = createSocket()
        userSignIn(username, addr, s)
	while True:
	        message = raw_input("+>")
	        if message == "list":
			userList(addr, s)

if __name__ == "__main__":
    main()
