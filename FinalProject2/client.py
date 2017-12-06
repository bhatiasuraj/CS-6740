#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: ChatClient.py

Description: Client side program for instant chat using UDP sockets in Python

Usage: python client.py -u USERNAME -sip server-ip -sp server-port

'''

from socket import *
import argparse
import sys
import select
import sys
import base64
import argparse
import sys
import os
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ast

sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/keyGen')
sys.path.insert(0, '/home/sbhatia/git/CS-6740/FinalProject/protobuf')

from fcrypt import AESEncryption
from fcrypt import AESDecryption
from fcrypt import RSAEncryption
from fcrypt import RSADecryption
from fcrypt import messageSigning
from fcrypt import messageVerification
from fcrypt import loadRSAPublicKey
from fcrypt import loadRSAPrivateKey

def prompt():

	sys.stdout.write('+> ')
	sys.stdout.flush()

def serverAuthentication(addr, socket):

	R1 = randint(0, 1000)

	firstMessage = {'message': "LOGIN", 'random': R1, 'user':username}

	cipherLogin = RSAEncryption(serverPubKey, str(firstMessage))

	socket.sendto(cipherLogin, addr)

	# socket.send_multipart([cipherLogin, username, user.SerializeToString()])

	helloMessage = socket.recv(65535)

	R1 += 1

	print helloMessage

	if int(helloMessage.split(" ")[1]) != R1:
		sys.exit("Verification failed!")

	R2 = randint(0, 1000)

	f = open(senderPubKeyFile, 'r')
	publicKeyFile = f.read()
	f.close()	
	
	secondCipherKey = RSAEncryption(serverPubKey, publicKeyFile)
	secondCipherNum = RSAEncryption(serverPubKey, str(R2))

	secondMessage = {"key":secondCipherKey, "random":secondCipherNum}

	secondHash = messageSigning(sendPriKey, str(secondMessage))

	secondMessage['hash'] = secondHash

	socket.sendto(str(secondMessage), addr)

	# socket.send_multipart([str(secondMessage), secondHash, user.SerializeToString()])

	challenge_dict = socket.recvfrom(65536)
	
	challenge_dict = ast.literal_eval(challenge_dict[0]) #Converting to dict
	
	challenge = RSADecryption(sendPriKey, challenge_dict['challenge'])		
	challenge_R2 = RSADecryption(sendPriKey, challenge_dict['random'])

	#incrementing R2
	R2 = int(R2)+1
	#print 'R2: '+ str(R2)
	#print 'Challenge R2: '+challenge_R2
	#Check if R2 is incremented
	if not R2 == int(challenge_R2):
		sys.exit("Random number doesnt match") 
	
	auth_status = 'fail'
	while (auth_status == 'fail'):
		uname = raw_input("Enter username: ")
		# Make password invisible
		password = raw_input("Enter password: ")

		#Hashing the password
		pass_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
		pass_digest.update(password)
		password = pass_digest.finalize()
		password = base64.b64encode(password)

		#finding answer of the challenge
		challenge_ans = break_hash(challenge)

		#Incrementing the random number
		R2 = int(R2)+1

		#Create the message dictionary
		thirdMessage = {"challenge_ans":challenge_ans, "random":R2, "uname" : uname, "password": password}

		#Encrypt the message and sign it then send

		thirdMessage = RSAEncryption(serverPubKey, str(thirdMessage))

		thirdHash = messageSigning(sendPriKey,thirdMessage)

		#Send challenge_and, uname, password to the server for authentication
		socket.sendto(str(thirdMessage)+"delimiter"+thirdHash, addr)

		#Receive message and see if server auth success or not 
		auth_msg = socket.recvfrom(65536)
		auth_msg = RSADecryption(sendPriKey, auth_msg[0])
		auth_msg = ast.literal_eval(auth_msg)

		R3 = R2+1
		if not R3 == auth_msg['random']:
			sys.exit("Random number doesnt match")

		# Terminate client session after three attempts
		if auth_msg['status'] == 'FAIL':
			print 'Incorrect credentials. Please try again.'
		elif auth_msg['status'] == 'KILL':
			sys.exit('All attempts exhausted. Start new session!!!')
		elif auth_msg['status'] == 'WELCOME':
			print 'Authentication Successful'
			auth_status = 'pass'			
			#Receive TokenId
			token_id = auth_msg['token_id']
			print 'TokenId: '+ token_id 
			return token_id

#Function used to bruteforce and find answer of the challenge
def break_hash(challenge_hash):
	#print "bruteforce begins"	
	for num in range(1,1000000):
		challenge_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    		challenge_digest.update(str(num))
		num_hash = challenge_digest.finalize()
		num_hash = base64.b64encode(num_hash)
		
		if num_hash == challenge_hash:
			return num



def sendToServer(message, socket, username, addr):

	# User SIGN-IN and send USERNAME to server
	if message == "SIGN-IN":
		try :
			socket.sendto("SIGN-IN "+username, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# For send command, request receiver information from server
	if message.split()[0] == "send":
		try :
			socket.sendto(message, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# Retrieve list of users connected to chat from server
	if message == "list":
		try :
			socket.sendto("list", addr)
			socket.settimeout(2)
			data, server = socket.recvfrom(65535)
			print str("<-"+data)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

	# Inform server that client is leaving chat
	if message == "exit":
		try :
			socket.sendto(message, addr)

		except error, msg:
			print 'Error Code : ' + str(msg)
			sys.exit()

def createSocket():

	# Create socket and handle failure
	try:
		clientSocket = socket(AF_INET, SOCK_DGRAM)

	except socket.error:
		print 'Failed to create socket'
		sys.exit(0)

	return clientSocket

def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()

	parser.add_argument("-u", help="USERNAME", required=True)
	parser.add_argument("-sip", help="server-ip", required=True)
	parser.add_argument("-sp", help="port", type=int, required=True)

	args = parser.parse_args()

	return args.u, args.sp, args.sip



parser = argparse.ArgumentParser()

parser.add_argument("-s", "--server",
            default="localhost",
            help="Server IP address or name")

parser.add_argument("-p", "--server-port", type=int,
            default=5569,
            help="port number of server to connect to")

parser.add_argument("-u", "--user",
            default="Alice",
            help="name of user")

parser.add_argument("-c", nargs='+',
	    help="Client Key List",
	    type=str)

parser.add_argument("-skey", nargs='+',
	    help="Server Public Key",
	    type=str)

args = parser.parse_args()

sendPriKey = loadRSAPrivateKey(args.c[1], "der")

sendPriKey = args.c[0]

username = args.user

sendPriKey = loadRSAPrivateKey(args.c[1], "der")

senderPubKeyFile = args.c[0]

#sendPubKey = loadRSAPublicKey(args.c[0], "der")

serverPubKey = loadRSAPublicKey(args.skey[0], "der")

# Retrieve username, server port and IP from command-line

server_addr = (args.server, args.server_port)

# Create client UDP socket
client_socket = createSocket()

# Send SIGN-IN message to server after socket creation
token_id = serverAuthentication(server_addr, client_socket)

prompt()

try:
	while True:

		# Manage list of different sockets
		socketList = [sys.stdin, client_socket]
		readSocket, writeSocket, errorSocket = select.select(socketList, [], [])

		for sock in readSocket:
			if sock == clientSocket:
				# Keep checking for received messages from server or other users
				try:
					data = clientSocket.recv(65535)

				except error:
					break

				if not data:
					sys.exit()

				else:
					# Retrieve receiver information from server to send message directly
					if data.split()[0] == "Send":
						receiverIp = data.split()[1]
						receiverPort = int(data.split()[2])
						receiver = (receiverIp, receiverPort)

						try:
							# Get actual message from send command
							m = message.split()[2]
							m = (' '.join(message.split(' ')[2:]))

							# Handle socket receiver buffer overflow
							if len(str(m)) <= 65494:
								clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+str(m)), receiver)

							# Send in chunks if total message larger > 65535
							else:
								clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[0:65494]), receiver)
								clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[65494:]), receiver)

						# Do not send empty messages
						except IndexError:
							print "\n<- Please enter some message!"

					# Exit from chat if server is down
					elif data == "Server Down.":
						print "\n+> Server disconnected, try again later."
						sys.exit()

					# Handle duplicate user log-in and exit
					elif data == "User "+username+" already exists.":
						sys.stdout.write('\n<- '+data+'\n')
						sys.exit()

					# Display any other legitimate messages from other users
					else:
						sys.stdout.write('\n<- '+data+'\n')

					prompt()
			else:
				# Take input from user
				message = raw_input()

				# Handle user exit
				if message == "exit":
					sendToServer(message, clientSocket, username, addr)
					clientSocket.close()
					sys.exit(0)

				# Blank command goes to next line
				elif message =="":
					prompt()

				# Check for message format
				elif message.split()[0] == "send":
					try:
						sendToServer(message, clientSocket, username, addr)

					except IndexError:
						print "+> Incorrect send format, please try again."
						prompt()

				# Request from server list of users logged in to chat
				elif message == "list":
					sendToServer(message, clientSocket, username, addr)
					prompt()

				# Handle invalid chat commands
				else:
					print "+> Command not supported, please try again."
					prompt()

# Handle keyboard interrup, notify server and exit from chat gracefully
except KeyboardInterrupt:
	sendToServer("exit", clientSocket, username, addr)
	clientSocket.close()
	sys.exit(0)


