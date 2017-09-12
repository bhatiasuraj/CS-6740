#!/usr/bin/python

from socket import *
import argparse

def signIn(s, u):
	username, addr = s.recvfrom(1024)
	# check for condition of duplicate user
	u[username] = addr
	userList = ', '.join(u.iterkeys())
	return userList, u

def sendMessage(socket, userDict, message, address):

	#Extracting sender name
	for key, value in userDict.items():
		if value == address:
			sender = key
	# Extracting receiver name 
	receiver = message.split()[1]
	# Extracting actual message to be sent 
	m = (' '.join(message.split(' ')[2:]))
	for key, value in userDict.items():
		if key == receiver:
			socket.sendto(str(" <From "+str(value[0])+":"+str(value[1])+":"+sender+"> "+m), value)

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
			sendMessage(serverSocket, userDict, message, address)

if __name__ == "__main__":
    main()

