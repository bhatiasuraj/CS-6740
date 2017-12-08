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
import cPickle
import pickle
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
from fcrypt import dh_keygen
from fcrypt import *

global logged_list
logged_list = dict()
server_iv  = ''

client_logged_list = dict()

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

		# Create DH keys

		dh_private_key, dh_public_key = dh_keygen()


		#Create the message dictionary
		thirdMessage = {"challenge_ans":challenge_ans, "random":R2, "uname" : uname, "password": password, 'dh_key': dh_public_key}

		thirdMessage = cPickle.dumps(thirdMessage)
		#Encrypt the message and sign it then send

		thirdMessage = RSAEncryption(serverPubKey, thirdMessage)

		thirdHash = messageSigning(sendPriKey,thirdMessage)

		#Send challenge_and, uname, password to the server for authentication
		socket.sendto(str(thirdMessage)+"delimiter"+thirdHash, addr)

		#Receive message and see if server auth success or not 
		auth_msg = socket.recvfrom(65536)

		#print auth_msg		

		try:
			auth_msg_dict = auth_msg[0]
			auth_msg_dict = auth_msg_dict.split("delimiter")[0]
			auth_msg_dict = RSADecryption(sendPriKey, auth_msg_dict)
			print auth_msg_dict
			auth_msg_dict = ast.literal_eval(auth_msg_dict)

			R3 = R2+1
			if not R3 == auth_msg_dict['random']:
				sys.exit("Random number doesnt match")

		except AttributeError:
			auth_msg_dict = RSADecryption(sendPriKey, auth_msg)
			auth_msg_dict = ast.literal_eval(auth_msg)

			R3 = R2+1
			if not R3 == auth_msg_dict['random']:
				sys.exit("Random number doesnt match")

		# Terminate client session after three attempts
		if auth_msg_dict['status'] == 'FAIL':
			print 'Incorrect credentials. Please try again.'
		elif auth_msg_dict['status'] == 'KILL':
			sys.exit('All attempts exhausted. Start new session!!!')
		elif auth_msg_dict['status'] == 'WELCOME':
			print 'Authentication Successful'
			auth_status = 'pass'			
			#Receive TokenId
			token_id = auth_msg_dict['token_id']

			server_dh_public_key = auth_msg[0].split("delimiter")[1]

			server_shared_key = dh_shared_keygen(dh_private_key, server_dh_public_key)


			print base64.b64encode(server_shared_key)

			print 'TokenId: '+ token_id 
			return token_id, server_shared_key, dh_private_key, dh_public_key

def c2c_auth(client_addr, dest_pub_key):

	status = 'NOTREGISTERED'
	client_shared_key = None

	dest_pub_key = serialization.load_der_public_key(dest_pub_key, backend=default_backend())

	token_hash = make_hash(token_id)


	f = open(senderPubKeyFile, 'r')
	publicKeyFile = f.read()
	f.close()	

	pk1 = publicKeyFile[0:len(publicKeyFile)/2]

	pk2 = publicKeyFile[len(publicKeyFile)/2:]

	enc_pk1 = RSAEncryption(dest_pub_key, pk1)

	enc_pk2 = RSAEncryption(dest_pub_key, pk2)
	
	#Dict with R1, token_hash and username
	R1 = randint(0,999)
	client_info = {'username':username, 'token_hash':token_hash, 'random':R1}

	enc_client_info = RSAEncryption(dest_pub_key, str(client_info))

	client_auth_msg = {'message':'CLI_AUTH', 'info':enc_client_info, 'pk1':enc_pk1, 'pk2':enc_pk2 }

	client_auth_msg = pickle.dumps(client_auth_msg)

	print "ALL DONE"

	client_socket.sendto(client_auth_msg, client_addr)
	
	DH_message = client_socket.recv(65535)
	DH_message = pickle.loads(DH_message)

	#Extracting random number from  encrypted DH_message
	random_num =RSADecryption(sendPriKey, DH_message['random'])
	print random_num 
	#Check if extracted R1 is incremented
	R1 += 1  #Incrementing original R1
	print R1
	if not str(R1) == str(random_num):
			sys.exit("Random number doesnt match")
	
	#Decrypting the DH_public key
	DH_client_pub_key = RSADecryption(sendPriKey, DH_message['key'])

	#Send DH_contribution to client
	CipherKey = RSAEncryption(dest_pub_key, dh_public_key)
	R1 += 1 #increment befor sending
	CipherNum = RSAEncryption(dest_pub_key, str(R1))
	DH_message = {"key":CipherKey, "random":CipherNum}	
	DH_message = pickle.dumps(DH_message)
	client_socket.sendto(DH_message, client_addr) 

	#Generate DH shared key
	client_shared_key = dh_shared_keygen(dh_private_key,DH_client_pub_key)
	print "sharedKEy:"
	print base64.b64encode(client_shared_key)
	
	#Check if shared key was generated and change status 
	if not client_shared_key == None: 
		status = 'REGISTERED'
		return status, client_shared_key
	else:
		return status, client_shared_key



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

			server_iv = os.urandom(16)

			listRequest = {'message':'LIST', 'token':token_id}

			cipher_list, e_tag = AESEncryption(server_shared_key, server_iv, str(listRequest))

			padded_iv = dataPadding(server_iv)

			cipher_list_dict = {'message':cipher_list, 'iv':padded_iv, 'tag':e_tag}

			cipher_list_dict = pickle.dumps(cipher_list_dict)
			
			socket.sendto(cipher_list_dict, addr)

			socket.settimeout(4)

			enc_data, server = socket.recvfrom(65535)

			enc_data = pickle.loads(enc_data)

			logged_list = AESDecryption(server_shared_key, server_iv, enc_data['tag'], enc_data['data'])

			logged_list = ast.literal_eval(logged_list)

			for key in logged_list:
				print key

			return logged_list

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
token_id, server_shared_key, dh_private_key, dh_public_key = serverAuthentication(server_addr, client_socket)

prompt()

authenticated_users = dict()

try:
	while True:

		# Manage list of different sockets
		socketList = [sys.stdin, client_socket]
		readSocket, writeSocket, errorSocket = select.select(socketList, [], [])

		for sock in readSocket:
			if sock == client_socket:
				# Keep checking for received messages from server or other users
				try:
					data, addr = client_socket.recvfrom(65535)

				except error:
					break

				if not data:
					sys.exit()

				else:

					try:
						data = pickle.loads(data)

												
					except:
						pass

					try:
						data = ast.literal_eval(data)

					except:
						pass

					if data['message'] == 'CHAT':
						chat_message = AESDecryption(client_shared_key, data['chat_iv'], data['chat_tag'], data['chat_message'])
						print 'msg_rcv:'						
						print chat_message

					if data['message'] == 'CLI_AUTH':
						
						dec_info = RSADecryption(sendPriKey, data['info'])
						dec_pk1 = RSADecryption(sendPriKey, data['pk1'])
						dec_pk2 = RSADecryption(sendPriKey, data['pk2'])
						 
						#Sending tokenid to server for verificaation
						new_iv = os.urandom(16)
						status_info, e_tag = AESEncryption(server_shared_key, new_iv, dec_info)
						token_verify_msg = {'message': 'CHECKTID', 'info':status_info, 'tag': e_tag, 'iv': new_iv}
						token_verify_msg = pickle.dumps(token_verify_msg)
						client_socket.sendto(token_verify_msg, server_addr)
						result = client_socket.recv(65535)

						if result == 'PASS':
							print "Passsed"
							dec_info = ast.literal_eval(dec_info)
							R1 = dec_info['random']
							token_hash = dec_info['token_hash']
							dest_username =  dec_info['username']
							#Recreating the client_public_key of destination
							dest_publicKeyFile = dec_pk1+dec_pk2

							#Start diffie Hellman exchange
							R1 += 1
							dest_publicKeyFile =serialization.load_der_public_key(dest_publicKeyFile, backend=default_backend())
							CipherKey = RSAEncryption(dest_publicKeyFile, dh_public_key)
							CipherNum = RSAEncryption(dest_publicKeyFile, str(R1))
							DH_message = {"key":CipherKey, "random":CipherNum}	
							DH_message = pickle.dumps(DH_message)
							client_socket.sendto(DH_message, addr)
							DH_peer_message = client_socket.recv(65535) 
							DH_peer_message = pickle.loads(DH_peer_message)

							#Extracting random number from  encrypted DH_message
							random_num =RSADecryption(sendPriKey, DH_peer_message['random'])
							 
							#Check if extracted R1 is incremented
							R1 += 1  #Incrementing original R1
							if not str(R1) == str(random_num):
									sys.exit("Random number doesnt match")
	
							#Decrypting the DH_public key
							DH_peer_pub_key = RSADecryption(sendPriKey, DH_peer_message['key'])
							print 'key received'

							#Generate DH shared key
							client_shared_key = dh_shared_keygen(dh_private_key,DH_peer_pub_key)
							print "sharedKEy:"
							print base64.b64encode(client_shared_key)
							
							#Add shared key to key dict
							client_logged_list[addr] = client_shared_key 
						else:
							print "Failed"
							client_socket.sendto('Wrong token id', addr)
						 

											

					'''
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
								client_socket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+str(m)), receiver)

							# Send in chunks if total message larger > 65535
							else:
								client_socket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[0:65494]), receiver)
								client_socket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[65494:]), receiver)

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

					'''
					prompt()
			else:
				# Take input from user
				user_input = raw_input()

				# Handle user exit
				if user_input == "exit":
					sendToServer(user_input, client_socket, username, server_addr)
					client_socket.close()
					sys.exit(0)

				# Blank command goes to next line
				elif user_input =="":
					prompt()

				# Check for message format
				elif user_input.split()[0] == "send":
					try:

						dest_client = user_input.split()[1]
						chat_message = user_input.split()[2]

						if dest_client in logged_list:
							client_addr = logged_list[dest_client][1]
							dest_pub_key = logged_list[dest_client][0]


						if not dest_client in authenticated_users:

							status,client_shared_key = c2c_auth(client_addr, dest_pub_key)
							client_logged_list[client_addr] = client_shared_key 

							#Encrypting the chat
							client_iv = os.urandom(16)							
							enc_chat, c_tag = AESEncryption(client_shared_key, client_iv, chat_message)
							chat_dict = {'message': 'CHAT', 'chat_iv':client_iv, 'chat_tag': c_tag, 'chat_message': enc_chat}
							chat_dict = pickle.dumps(chat_dict)
							client_socket.sendto(chat_dict, client_addr)							
						
						#client_socket.sendto(user_input.split(" ")[2], client_addr)

					except IndexError:
						print "+> Incorrect send format, please try again."
						prompt()
				

					

				# Request from server list of users logged in to chat
				elif user_input == "list":
					logged_list = sendToServer(user_input, client_socket, username, server_addr)
					prompt()

				# Handle invalid chat commands
				else:
					print "+> Command not supported, please try again."
					prompt()

# Handle keyboard interrup, notify server and exit from chat gracefully
except KeyboardInterrupt:
	sendToServer("exit", client_socket, username, server_addr)
	client_socket.close()
	sys.exit(0)


