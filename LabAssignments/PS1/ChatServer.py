#!/usr/bin/python

from socket import *
import argparse
import sys

def signIn(s, u, message, address):
	
	if message == "SIGN-IN":
		username, addr = s.recvfrom(1024)
	
	# Check for duplicate user
		u[username] = addr
	
	if message == "exit":
		for key, value in u.items():
			if value == address:
				del u[key]

	userList = ', '.join(u.iterkeys())
	return userList, u
		

def sendMessage(socket, userDict, message, address):

	# Extracting sender name
	for key, value in userDict.items():
		if value == address:
			sender = key

	# Extracting receiver name
	try:	 
		receiver = message.split()[1]
	except IndexError:
		socket.sendto("Please specify receiver!", address)
		return

	# Extracting actual message to be sent
		m = (' '.join(message.split(' ')[2:]))

	for key, value in userDict.items():
		if key == receiver:
			socket.sendto("Send "+str(value[0])+" "+str(value[1]), address)
			return

	# Check for user not logged into chat	
	socket.sendto("No such user logged in, try again.", address)

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
			message, address = serverSocket.recvfrom(1024)

			if message == "SIGN-IN":
				userString, userDict = signIn(serverSocket, userList, message, address)

			if message == "list":
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

