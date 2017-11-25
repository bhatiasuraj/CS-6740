#!/usr/bin/env python
#
'''
Simple Chat Program that allows users to register, request the list of registered users,
and send a message to another user through the server. This code can get you started with
your CS4740/6740 project.
Note, that a better implementation would use google protobuf more extensively, with a
single message integrating both control information such as command type and other fields.
See the other provided tutorial on Google Protobuf.
Also, note that the services provided by this sample project do not nessarily satisfy the
functionality requirements of your final instant messaging project.
Finally, we use DEALER and ROUTER to be able to communicate back and forth with multiple
clients (ROUTER remembers identities [first part of message] when it receives a message and
prepends identity to messages when sending to DEALER). See:
  http://zguide.zeromq.org/php:chapter3.
'''

__author__      = "Guevara Noubir"


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

import messaging_app_pb2

def clientAuthentication(serverPubKey, serverPriKey):

	firstMessage = socket.recv_multipart()

	ident =  firstMessage[0]

	loginMessage = RSADecryption(serverPriKey, firstMessage[1])

	R1 = loginMessage[7:]

	R1 = int(R1) + 1

	socket.send_multipart([ident, "HELLO "+str(R1)])

	secondMessage = socket.recv_multipart()
	
	#converting str to dict	
	msg_dict = ast.literal_eval(secondMessage[1])	
	
	client_pub_key_encrypted = msg_dict['key']
	R2_encrypted = msg_dict['random']

	#Decrypting and loading the client_pub_key
	client_pub_key = RSADecryption(serverPriKey, client_pub_key_encrypted)	
	client_pub_key = serialization.load_der_public_key(client_pub_key, backend=default_backend())
	
	#use client pub key to verify the signature
	if not messageVerification(client_pub_key,secondMessage[1],secondMessage[2]):
		sys.exit("Signature verification failed! Messege not from clint")
	
	#Decrypting R2 and incrementing it
	R2 = RSADecryption(serverPriKey, R2_encrypted)
	print 'R2 decrypted: '+str(R2)
	R2 = int(R2)+1
	print 'incremented R2: '+str(R2)
	#send challenge
	challenge_num = random.randint(10000,99999) #generate random 5 digit number	
	challenge = create_challenge(challenge_num)

	
	
	#Encrypting the challenge
	challenge_cipher = RSAEncryption(client_pub_key, challenge)
	challenge_random = RSAEncryption(client_pub_key, str(R2))
	print "challenge encryption sucessfull"

	challenge_dict = {'challenge': challenge_cipher, 'random': challenge_random}
	
	socket.send_multipart([ident, str(challenge_dict)])

	#verify challenge answer, password
	thirdMessage = socket.recv_multipart()
	
	#Check the signature  
	#use client pub key to verify the signature
	if not messageVerification(client_pub_key,thirdMessage[1],thirdMessage[2]):
		sys.exit("Signature verification failed! Messege not from clint")
	print 'Signature verification successful'
	
	#Decrypting the messege to retrieve the challenge answer, uname, password
	thirdMessage_dict = RSADecryption(serverPriKey, thirdMessage[1])	
	
	challenge_msg_dict = ast.literal_eval(thirdMessage_dict)
	
	challenge_ans =  challenge_msg_dict['challenge_ans']
	uname = challenge_msg_dict['uname']
	password = challenge_msg_dict['password']
	random_num = challenge_msg_dict['random']
	
	#Increment and Check random number
	R2 = R2+1
	if not R2 == random_num:
		sys.exit("Random number doesnt match")
	
	#Username, Password authentication
	if not password_authenticate(uname, password):
		return "auth failed no token id generated"		
		

	#send WELCOME and TOKENID



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
	print 'Incorrect credentials. Please try again'
	return False

		

parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

parser.add_argument("-s", nargs='+',
		    help="Server Key List",
		    type=str)

args = parser.parse_args()

serverPubKey = loadRSAPublicKey(args.s[0], "der")
serverPriKey = loadRSAPrivateKey(args.s[1], "pem")

#  Prepare our context and sockets
context = zmq.Context()

# We are using the DEALER - ROUTER pattern see ZMQ docs
socket = context.socket(zmq.ROUTER)
socket.bind("tcp://*:%s" %(args.server_port))

# store registered users in a dictionary
logged_users = dict()
logged_ident = dict()

clientAuthentication(serverPubKey, serverPriKey)

# main loop waiting for users messages
while(True):

    message = socket.recv_multipart()

    # Remeber that when a ROUTER receives a message the first part is an identifier
    #  to keep track of who sent the message and be able to send back messages
    ident = message[0]

    print("Received [%s]" % (message[1]))

    if len(message) == 2:
    	if message[1]== 'LIST':

            # If first seeing this identity sent back ERR message requesting a REGISTER
    		if ident not in logged_ident:
    			socket.send_multipart([ident, b'ERR', b'You need to register first.'])
    		else:

	    		print("List request from user %s" %(logged_ident[ident]))
    			socket.send_multipart([ident, b'LIST', base64.b64encode(str(logged_users))])

    if len(message) == 4:
    	if message[1] == 'REGISTER':
    		logged_users[message[2]] = ident
    		logged_ident[ident] = message[2]
    		user = messaging_app_pb2.User()
    		user.ParseFromString(message[3])
    		print ("Registering %s" % (user.name))
    		socket.send_multipart([ident, b"REGISTER", b'Welcome %s!' %(str(user.name))])

    if len(message) == 4:
    	if message[1] == 'SEND':
    		# check if destination is registered, retrieve address, and forward
    		if message[2] in logged_users:
    			print "sending message to %s" %(message[2])

                # Note that message from ROUTER is prepended by destination ident
    			socket.send_multipart([logged_users[message[2]], b'MSG', message[3]])
    		else:
    			socket.send_multipart([ident, b'ERR', message[2] + b' not registered.'])
