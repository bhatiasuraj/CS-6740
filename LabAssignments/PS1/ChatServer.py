#!/usr/bin/python

from socket import *
import argparse

def signIn(s, u):
	username, addr = s.recvfrom(1024)
	u[username] = addr
	userList = ', '.join(u.iterkeys())
	return userList

def sendMessage(s, u, m):
	receiver = m.split()[1]
	print receiver


def main():

	parser = argparse.ArgumentParser()
	parser.add_argument("-sp", help="port", type=int)
	args = parser.parse_args()

	serverSocket = socket(AF_INET, SOCK_DGRAM)

	serverSocket.bind(('', args.sp))
	print("Server Initialized...")
	userList = {}

	while True:
		message, address = serverSocket.recvfrom(1024)

		if message == "SIGN-IN":
			u = signIn(serverSocket, userList)

		if message == "list":
			serverSocket.sendto("Signed in Users: "+str(u), address)
	
		if message.split()[0] == "send":
			sendMessage(serverSocket, u, message)

if __name__ == "__main__":
    main()

