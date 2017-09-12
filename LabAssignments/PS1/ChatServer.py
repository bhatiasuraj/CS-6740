#!/usr/bin/python

from socket import *
import argparse

def signIn(s, u):
	username, addr = s.recvfrom(1024)
	u[username] = addr
	userList = ', '.join(u.iterkeys())
	return userList, u

def sendMessage(s, u, m):
	receiver = m.split()[1]
	for key, value in u.items():
		if key == receiver:
			print "Receiver is "+receiver


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
			userString, userDict = signIn(serverSocket, userList)

		if message == "list":
			serverSocket.sendto("Signed in Users: "+str(userString), address)
	
		if message.split()[0] == "send":
			sendMessage(serverSocket, userDict, message)

if __name__ == "__main__":
    main()

