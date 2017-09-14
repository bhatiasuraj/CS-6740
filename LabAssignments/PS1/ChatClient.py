'''

Author: Suraj Bhatia

Title: ChatClient.py

Description: Client side program for instant chat using UDP sockets in Python

Usage: python ChatClient.py -u USERNAME -sip server-ip -sp server-port 

'''

#!/usr/bin/python

from socket import *
import argparse
import sys
import select

def prompt():

	sys.stdout.write('+> ')
	sys.stdout.flush()

def sendToServer(message, socket, username, addr):

	# User SIGN-IN and send USERNAME to server
	if message == "SIGN-IN":
		try :
			socket.sendto("SIGN-IN "+username, addr)

		except error, msg:
        		print 'Error Code : ' + str(msg)
        		sys.exit()
				

	if message.split()[0] == "send":
		try :			
			socket.sendto(message, addr)			

		except error, msg:
        		print 'Error Code : ' + str(msg)
        		sys.exit()

	if message == "list":
		try :
			socket.sendto("list", addr)
			socket.settimeout(2)
			data, server = socket.recvfrom(65535)
			print str("<-"+data)

		except error, msg:
        		print 'Error Code : ' + str(msg)
        		sys.exit()

	if message == "exit":
		try :
			socket.sendto(message, addr)

		except error, msg:
        		print 'Error Code : ' + str(msg)
        		sys.exit()		

def createSocket(ip, port):

	try:
		clientSocket = socket(AF_INET, SOCK_DGRAM)

	except socket.error:
    		print 'Failed to create socket'
    		sys.exit(0)
	
	return clientSocket

def argsParser():

        parser = argparse.ArgumentParser()

        parser.add_argument("-u", help="USERNAME", required=True)
        parser.add_argument("-sip", help="server-ip", required=True)
        parser.add_argument("-sp", help="port", type=int, required=True)

	args = parser.parse_args()

	return args.u, args.sp, args.sip

def main():

	username, port, ip = argsParser()
	addr = (ip, port)

	# Create client UDP socket
	clientSocket = createSocket(ip, port)	

	# Send SIGN-IN message to server after socket creation
	sendToServer("SIGN-IN", clientSocket, username, addr)
	prompt()

	try:
		while True:

			socketList = [sys.stdin, clientSocket]
			readSocket, writeSocket, errorSocket = select.select(socketList, [], [])

			for sock in readSocket:
				if sock == clientSocket:
					try:
						data = clientSocket.recv(65535)

					except error:
						break

					if not data:
						sys.exit()

					else:
						if data.split()[0] == "Send":
							receiverIp = data.split()[1]
							receiverPort = int(data.split()[2])

							receiver = (receiverIp, receiverPort)
							try:							
								m = message.split()[2]
								m = (' '.join(message.split(' ')[2:]))

								if len(str(m)) <= 65494:
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+str(m)), receiver)
								else:
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[0:65494]), receiver)
									clientSocket.sendto(str("<From "+str(ip)+":"+str(port)+":"+username+">: "+m[65494:]), receiver)
							except IndexError:
								print "<- Please enter some message"	
							
						elif data == "Server Down.":
							print "\n+> Server disconnected, try again later"
							sys.exit()

						elif data == "User "+username+" already exists":
							sys.stdout.write('\n<- '+data+'\n')
							sys.exit()
											
						else:
							sys.stdout.write('\n<- '+data+'\n')
					
						prompt()
				else:
					message = raw_input()

					if message == "exit":
						sendToServer(message, clientSocket, username, addr)
						clientSocket.close()
						sys.exit(0)

					elif message =="":
						prompt()

					# Check for message format
					elif message.split()[0] == "send":
						try:
							sendToServer(message, clientSocket, username, addr)

						except IndexError:
							print "+> Incorrect send format, try again"
							prompt()
	
					elif message == "list":
						sendToServer(message, clientSocket, username, addr)
						prompt()
					else:
						print "+> Command not supported"
						prompt()
	except KeyboardInterrupt:
		sendToServer("exit", clientSocket, username, addr)
		clientSocket.close()
		sys.exit(0)
		
		
if __name__ == "__main__":
    main()
