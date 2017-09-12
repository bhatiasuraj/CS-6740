#!/usr/bin/python

from socket import *
import threading
import argparse
import sys
import select

def prompt():
	sys.stdout.write('+> ')
	sys.stdout.flush()

def sendToServer(message, socket, username, addr):
	if message == "SIGN-IN":
		socket.sendto("SIGN-IN", addr)
		socket.sendto(username, addr)		

	if message.split()[0] == "send":
		socket.sendto(message, addr)

	if message == "list":
		socket.sendto("list", addr)
		data, server = socket.recvfrom(1024)
		print str("<-"+data)

	if message == "exit":
		socket.sendto(message, addr)
		

def createSocket():
	clientSocket = socket(AF_INET, SOCK_DGRAM)
	#clientSocket.bind((ip, port))
	return clientSocket

def argsParser():

        parser = argparse.ArgumentParser()

        parser.add_argument("-u", help="USERNAME")
        parser.add_argument("-sip", help="server-ip")
        parser.add_argument("-sp", help="port", type=int)
	args = parser.parse_args()

	return args.u, args.sp, args.sip

def main():

	username, port, ip = argsParser()
	addr = (ip, port)
	clientSocket = createSocket()	

	sendToServer("SIGN-IN", clientSocket, username, addr)
	prompt()
	while True:
		socketList = [sys.stdin, clientSocket]
		readSocket, writeSocket, errorSocket = select.select(socketList, [], [])
		for sock in readSocket:
			if sock == clientSocket:
				try:
					data = clientSocket.recv(1024)
				except:
					break
				if not data:
					sys.exit()
				else:
					if data.split()[0] == "Send":
						receiverIp = data.split()[1]
						receiverPort = int(data.split()[2])
						receiver = (receiverIp, receiverPort)
						clientSocket.sendto(str(" <From "+str(ip)+":"+str(port)+":"+username+">: "+str(message.split()[2:])), receiver)
					
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

		
				elif message.split()[0] == "send":
					sendToServer(message, clientSocket, username, addr)
					
					
				else:
					sendToServer(message, clientSocket, username, addr)
					prompt()


		
if __name__ == "__main__":
    main()


'''def recvFromServer(clientSocket):

	clientSocket.setblocking(0)
	ready = select.select([clientSocket], [], [], 1)
	if ready[0]:	
		data = clientSocket.recv(1024)
		if data:
			print "<- "+data

'''

