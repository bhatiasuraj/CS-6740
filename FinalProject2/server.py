#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: ChatServer.py

Description: Server side program for instant chat using UDP sockets in Python

Usage: python server.py -sp server-port

'''

from socket import *
import argparse
import sys
import zmq
import sys
import time
import base64
import argparse
import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import random
import ast
from cryptography.hazmat.primitives import serialization

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

def clientAuthentication(socket, addr, R1):

	#Increment received R1
	R1 = int(R1) + 1

	socket.sendto("HELLO "+str(R1), addr)

	secondMessage = socket.recv(65536)

	print secondMessage
	
	#converting str to dict
	secondMessage = ast.literal_eval(secondMessage)
	
	client_pub_key_encrypted = secondMessage['key']
	R2_encrypted = secondMessage['random']
	msg_sign = secondMessage['hash']

	del secondMessage['hash']

	msg_dict_verify = secondMessage

	print msg_dict_verify
	
	#Decrypting and loading the client_pub_key
	client_pub_key = RSADecryption(serverPriKey, client_pub_key_encrypted)	
	client_pub_key = serialization.load_der_public_key(client_pub_key, backend=default_backend())
	
	#use client pub key to verify the signature
	if not messageVerification(client_pub_key,str(msg_dict_verify),msg_sign):
		sys.exit("Signature verification failed! Messege not from clint")
	
	#Decrypting R2 and incrementing it
	R2 = RSADecryption(serverPriKey, R2_encrypted)
	#print 'R2 decrypted: '+str(R2)
	R2 = int(R2)+1
	#print 'incremented R2: '+str(R2)
	#send challenge
	challenge_num = random.randint(10000,99999) #generate random 5 digit number	
	challenge = create_challenge(challenge_num)

	
	
	#Encrypting the challenge
	challenge_cipher = RSAEncryption(client_pub_key, challenge)
	challenge_random = RSAEncryption(client_pub_key, str(R2))
	#print "challenge encryption sucessfull"

	challenge_dict = {'challenge': challenge_cipher, 'random': challenge_random}
	
	socket.sendto(str(challenge_dict), addr)


	attempt_count = 0
	auth_flag = False
	while (attempt_count != 3) and (not auth_flag):
		#verify challenge answer, password
		thirdMessage = socket.recvfrom(65536)
		print thirdMessage

		thirdMessage = thirdMessage[0].split("delimiter")
		
		
		#Check the signature  
		#use client pub key to verify the signature
		if not messageVerification(client_pub_key,thirdMessage[0],thirdMessage[1]):
			sys.exit("Signature verification failed! Messege not from clint")
		#print 'Signature verification successful'
	
		#Decrypting the messege to retrieve the challenge answer, uname, password
		thirdMessage_dict = RSADecryption(serverPriKey, thirdMessage[0])	
	
		challenge_msg_dict = ast.literal_eval(thirdMessage_dict)
	
		challenge_ans =  challenge_msg_dict['challenge_ans']
		uname = challenge_msg_dict['uname']
		password = challenge_msg_dict['password']
		random_num = challenge_msg_dict['random']
	
		#Increment and Check random number
		R2 = R2+1
		#print R2
		#print random_num
		if not R2 == random_num:
			sys.exit("Random number doesnt match")
	
		#Username, Password authentication
 
		if not password_authenticate(uname, password):
			if attempt_count < 2:			
				attempt_count += 1	
				R3 = R2 + 1	
				auth_msg = {'status': 'FAIL', 'random':R3}	
				auth_msg = RSAEncryption(client_pub_key, str(auth_msg))
				socket.sendto(auth_msg, addr)
			elif attempt_count == 2:
				attempt_count += 1
				R3 = R2 + 1
				kill_msg = {'status': 'KILL', 'random':R3}
				kill_msg = RSAEncryption(client_pub_key, str(kill_msg))
				socket.sendto(kill_msg, addr)	 		
		else:
			R3 = R2 + 1
			#Generating token id 
			token_id = str(addr) + ':' + str(challenge_ans)
			token_msg = {'status': 'WELCOME', 'random': R3, 'token_id' : token_id}
			token_msg = RSAEncryption(client_pub_key, str(token_msg))
			socket.sendto(token_msg, addr)			
			auth_flag = True

	#Kill connection if all authentication attempts exhausted 	
	if not auth_flag:
		#returning status and token_id
		return 'LOGIN FAIL', None   #Send None as token_id, if login fails 	
	else:
		return 'LOGIN SUCCESS', token_id, client_pub_key
	
	

#Function to send the challenge to the client
def create_challenge(challenge_num):    

    #hash the random number created above
    challenge_digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    challenge_digest.update(str(challenge_num))
    challenge_hash = challenge_digest.finalize()
    challenge_hash = base64.b64encode(challenge_hash)

    return challenge_hash



#Function to authenticate the username and password from the serverConf file
def password_authenticate(uname, password):
	for line in open("serverConf.conf","r").readlines(): # Read the lines
		login_info = line.split(':') # Split on the space, and store the results in a list of two strings
		if uname == login_info[0] and password == login_info[1][:-1]:
			print 'Authentication Sucessfull!!!'                
			return True
	print 'Incorrect credentials.'
	return False

		

def signIn(serverSocket, userDatabase, message, address):

	# Receieve username after sign-in
	if message.split()[0] == "SIGN-IN":
		username = message.split()[1]

	# Check for duplicate user, add new USER to database
		if username not in userDatabase:
			userDatabase[username] = address
		else:
			serverSocket.sendto("User "+username+" already exists", address)

	# Handle user exit and remove from logged-in database
	if message == "exit":
		for key, value in userDatabase.items():
			if value == address:
				del userDatabase[key]

	userList = ', '.join(userDatabase.iterkeys())

	return userList, userDatabase


def sendMessage(serverSocket, userDatabase, message, address):

	# Extracting sender name
	for key, value in userDatabase.items():
		if value == address:
			sender = key

	# Extracting receiver name, handling error for no RECEIVER given
	try:
		receiver = message.split()[1]
	except IndexError:
		serverSocket.sendto("Please specify receiver!", address)
		return

	# Extracting actual message to be sent
		m = (' '.join(message.split(' ')[2:]))

	# Send receiever information to sender
	for key, value in userDatabase.items():
		if key == receiver:
			serverSocket.sendto("Send "+str(value[0])+" "+str(value[1]), address)
			return

	# Check for user not logged into chat
	serverSocket.sendto("No such user logged in, try again.", address)


def createSocket(serverPort):

	# Create Server socket
	try:
		serverSocket = socket(AF_INET, SOCK_DGRAM)

	# Socket create error handle
	except error, createError:
		print "Failed to create socket. Error: "+str(creatError)
		sys.exit(0)

	# Bind socket to all its interfaces and the specified port number
	try:
		serverSocket.bind(('', serverPort))
		print("Server Initialized...")

	# Socket create error handle
	except error, bindError:
		print "Failed to bind socket. Error: "+str(bindError)
		sys.exit(0)

	return serverSocket



parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
            default=5569,
            help="port number of server to connect to")

parser.add_argument("-s", nargs='+',
	    help="Server Key List",
	    type=str)

args = parser.parse_args()

serverPubKey = loadRSAPublicKey(args.s[0], "der")
serverPriKey = loadRSAPrivateKey(args.s[1], "der")

# Parse command line arguments for server port number

# Create server socket
serverSocket = createSocket(args.server_port)

# Maintain dictionary mapping of username and addresses
logged_users = dict()
logged_ident = dict()
token_id_dict = dict()
logged_users_keys = dict()

try:
	while True:
		print 'Server Listening'
		# Wait for messages to be received infinitely. handle accordingly
		message, addr = serverSocket.recvfrom(65535)

		try:
			message = RSADecryption(serverPriKey, message)
		except ValueError:
			print "ERROR"

		try:
			message = ast.literal_eval(message)
		except ValueError:
			continue

		if message['message'] == "LOGIN":
			clientAuthentication(serverSocket, addr, message['random'])
			

		if message['message'] == "list":
			serverSocket.sendto(" Signed in Users: "+str(userString), address)

		if message['message'] == "send":
			sendMessage(serverSocket, userDatabase, message, address)

		if message['message'] == "exit":
			userString, userDatabase = signIn(serverSocket, userDatabase, message, address)

	serverSocket.close()

# Handle keyboard interrupt and inform connected clients of break down
except KeyboardInterrupt:
	for key, value in userDatabase.items():
		serverSocket.sendto("Server Down.", value)


