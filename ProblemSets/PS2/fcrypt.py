# -*- coding: utf-8 -*-
#!/usr/bin/python3

'''

Author: Suraj Bhatia

Title: fcrypt.py

Description: 

Usage: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

       python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file

'''

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import padding as paddingFunction

from socket import *
import argparse
import sys
import os
import base64
import os.path


def AESEncryption(key, associatedData, iv, pt):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

 	encryptor = cipher.encryptor()

    	encryptor.authenticate_additional_data(associatedData)

	ct = encryptor.update(pt) + encryptor.finalize()

	return ct, encryptor.tag

def AESDecryption(key, associatedData, iv, tag, ct):

	cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())

	decryptor = cipher.decryptor()

	decryptor.authenticate_additional_data(associatedData)

	pt = decryptor.update(ct) + decryptor.finalize()

	return pt


def RSAEncryption(key, message):
	
	cipherKey = key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))

    	return cipherKey

def dataPadding(data):

	padder = paddingFunction.PKCS7(128).padder()

	paddedData = padder.update(data)

	paddedData += padder.finalize()

	return paddedData

def dataUnpadding(paddedData):

	unpadder = paddingFunction.PKCS7(128).unpadder()
	
	data = unpadder.update(paddedData)

	data += unpadder.finalize()

	return data


def loadRSAPublicKey(publicKeyFile, ext):      

	with open(publicKeyFile, "rb") as keyFile:

		if ext == 'der':
        		publicKey = serialization.load_der_public_key(keyFile.read(), backend=default_backend())

		else:
			publickey = serialization.load_pem_public_key(keyFile.read(), backend=default_backend())

		return publicKey


def loadRSAPrivateKey(privateKeyFile, ext):
	
	with open(privateKeyFile, "rb") as keyFile:

	        if ext =='der':
			privateKey = serialization.load_der_private_key(keyFile.read(),password = None,backend = default_backend())
	        else:
			privateKey = serialization.load_pem_private_key(keyFile.read(),password = None,backend = default_backend())

	return privateKey
	
def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()

	parser.add_argument("-e", nargs='+', help="Encryption Parameter List", type=str)
	parser.add_argument("-d", nargs='+', help="Decryption Parameter List", type=str)

	args = parser.parse_args()	

	if args.e != 'None' and len(args.e) == 4:
		return args.e, "e"
	else:
		print "Four paramaters required, try again."
		sys.exit()

	if args.d != 'None' and len(args.d) == 4:
		return args.d, "d"
	else:
		print "Four paramaters required, try again."
		sys.exit()

	
def main():

	# Retrieve parameter list for encryption/decryption operation from command-line
	
	paramList, operation  = argsParser()

	print paramList

	ext = os.path.splitext(paramList[0])[1].split('.')[1]
	
	destPubKey = loadRSAPublicKey(paramList[0], ext)

	sendPriKey = loadRSAPrivateKey(paramList[1], ext)

	ipFile = paramList[2]

	opFile = paramList[3]

	key = os.urandom(32)

	iv = os.urandom(16)

	firstName = base64.b64decode('z4DPhc+BzrHPgA====') 	#πυραπ
	lastName = base64.b64decode('zrLOt86xz4TOuc6x==')  	#βηατια

	associatedData = firstName+lastName

	pt = open(ipFile, "rb").read()

	print pt

        outputFile = open(opFile, "wb")

	ct, tag = AESEncryption(key, associatedData, iv, pt)

	outputFile.write(ct)

	outputFile.write(firstName)

	cipherKey = RSAEncryption(destPubKey, key)

	paddedIV = dataPadding(iv)

	print paddedIV

	outputFile.write(cipherKey+paddedIV)
		
	print AESDecryption(key, associatedData, iv, tag, ct)



if __name__ == "__main__":
    main()

