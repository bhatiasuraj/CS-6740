'''

Author: Suraj Bhatia

Title: ChatServer.py

Description: Server side program for instant chat using UDP sockets in Python

Usage: python ChatServer.py -sp server-port 

'''

#!/usr/bin/python

from socket import *
import argparse
import sys

def signIn(serverSocket, u, message, address):
	
	# Receieve username after sign-in
	if message == "SIGN-IN":
		username, addr = serverSocket.recvfrom(65535)
	
	# Check for duplicate user
		if username not in u:
			u[username] = addr
		else:
			serverSocket.sendto("User "+username+" already exists", address)

	# Handle user exit
	if message == "exit":
		for key, value in u.items():
			if value == address:
				del u[key]

	userList = ', '.join(u.iterkeys())

	return userList, u
		

def sendMessage(serverSocket, userDict, message, address):

	# Extracting sender name
	for key, value in userDict.items():
		if value == address:
			sender = key

	# Extracting receiver name
	try:	 
		receiver = message.split()[1]
	except IndexError:
		serverSocket.sendto("Please specify receiver!", address)
		return

	# Extracting actual message to be sent
		m = (' '.join(message.split(' ')[2:]))

	for key, value in userDict.items():
		if key == receiver:
			serverSocket.sendto("Send "+str(value[0])+" "+str(value[1]), address)
			return

	# Check for user not logged into chat	
	serverSocket.sendto("No such user logged in, try again.", address)

def argsParser():

	parser = argparse.ArgumentParser()
	parser.add_argument("-sp", help="port", type=int)
	args = parser.parse_args()

	return args.sp

def createSocket(serverPort):

	try:
		serverSocket = socket(AF_INET, SOCK_DGRAM)

	except socket.error, createError:
		print "Failed to create socket. Error: "+str(creatError) 
		sys.exit(0)

	try:
		serverSocket.bind(('', serverPort))
		print("Server Initialized...")

	except socket.error, bindError:
		print "Failed to bind socket. Error: "+str(bindError) 
	
	return serverSocket
			
def main():


	serverPort = argsParser()
	
	serverSocket = createSocket(serverPort)
		
	userList = {}

	try:
		while True:
			message, address = serverSocket.recvfrom(65535)

			if message == "SIGN-IN":
				userString, userDict = signIn(serverSocket, userList, message, address)

			if message == "list":
				#print len(message)
				serverSocket.sendto(" Signed in Users: "+str(userString), address)
	
			if message.split()[0] == "send":
				sendMessage(serverSocket, userDict, message, address)
		
			if message == "exit":
				userString, userDict = signIn(serverSocket, userList, message, address)

		serverSocket.close()

	except KeyboardInterrupt:
		for key, value in userDict.items():
			serverSocket.sendto("Server Down.", value)		

if __name__ == "__main__":
    main()

