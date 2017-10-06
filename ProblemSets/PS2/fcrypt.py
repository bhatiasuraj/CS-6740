# -*- coding: utf-8 -*-
#!/usr/bin/python

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
import cryptography

from socket import *
import argparse
import sys
import os
import base64

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

def HASHFunction(data, key):
	
	h = hmac.HMAC(key, hashes.SHA512(), backend=default_backend())
	
	h.update(data)

	messageDigest = h.finalize()
	
	return messageDigest

def RSAEncryption(key, message):
	
	cipherKey = key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))

    	return cipherKey

def RSADecryption(key, cipherKey):

	key = key.decrypt(cipherKey,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA512()),algorithm = hashes.SHA256(),label = None))
	
	return key

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

def messageSigning(sendPriKey, message):

	signer = sendPriKey.signer(padding.PSS(mgf = padding.MGF1(hashes.SHA512()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA512())

	signer.update(message)

	signature =  signer.finalize()

	return signature

def messageVerification(sendPubKey, message, signature):

	verifier = sendPubKey.verifier(signature,padding.PSS(mgf = padding.MGF1(hashes.SHA512()), salt_length = padding.PSS.MAX_LENGTH), hashes.SHA512())

	verifier.update(message)

	try:
        	verifier.verify()
        	return True

    	except:
        	return False

def loadRSAPublicKey(publicKeyFile, keyType):      

	with open(publicKeyFile, "rb") as keyFile:

		if keyType == 'der':
        		publicKey = serialization.load_der_public_key(keyFile.read(), backend=default_backend())

		elif keyType == 'pem':
			publicKey = serialization.load_pem_public_key(keyFile.read(), backend=default_backend())

		else:
			sys.exit("Unknown key type.")

	return publicKey

def loadRSAPrivateKey(privateKeyFile, keyType):
	
	with open(privateKeyFile, "rb") as keyFile:

		if keyType == 'der':
			privateKey = serialization.load_der_private_key(keyFile.read(),password = None,backend = default_backend())
		
		elif keyType == "pem":
			privateKey = serialization.load_pem_private_key(keyFile.read(),password = None,backend = default_backend())

		else:
			sys.exit("Unknown key type.")

	return privateKey
	
def argsParser():

	# Command-line arguments parser
	parser = argparse.ArgumentParser()

	parser.add_argument("-e", nargs='+', help="Encryption Parameter List", type=str)
	parser.add_argument("-d", nargs='+', help="Decryption Parameter List", type=str)

	args = parser.parse_args()	

	if args.e:

		if args.e != 'None' and len(args.e) == 4:
			return args.e, "e"
		else:
			print "Four paramaters required, try again."
			sys.exit()

	elif args.d:
		if args.d != 'None' and len(args.d) == 4:
			return args.d, "d"
		else:
			print "Four paramaters required, try again."
			sys.exit()

def Encryption(paramList, operation, firstName, lastName, associatedData):

	keyType = os.path.splitext(paramList[0])[1].split('.')[1]
	
	destPubKey = loadRSAPublicKey(paramList[0], keyType)
	sendPriKey = loadRSAPrivateKey(paramList[1], keyType)
	ptFile = paramList[2]
	ctFile = paramList[3]

	key = os.urandom(32)
	iv = os.urandom(16)

	pt = open(ptFile, "rb").read()

        outputFile = open(ctFile, "wb")

	ct, tag = AESEncryption(key, associatedData, iv, pt)

	outputFile.write(ct)
	outputFile.write(firstName)

	cipherKey = RSAEncryption(destPubKey, key)

	paddedIV = dataPadding(iv)

	outputFile.write(cipherKey+paddedIV)
	outputFile.write(lastName)

	messageDigest = HASHFunction(ct+cipherKey, key)

	outputFile.write(messageDigest +base64.b64encode(str(len(cipherKey))))
	outputFile.write(firstName)

	fullMessage = ct + cipherKey + paddedIV + messageDigest

	signedMessage = messageSigning(sendPriKey, fullMessage)

	outputFile.write(signedMessage)
	outputFile.write(lastName)
	outputFile.write(tag)

        outputFile.close()

def Decryption(paramList, operation, firstName, lastName, associatedData):

	keyType = os.path.splitext(paramList[0])[1].split('.')[1]

	destPriKey = loadRSAPrivateKey(paramList[0], keyType)
	sendPubKey = loadRSAPublicKey(paramList[1], keyType)
	ctFile = paramList[2]
	ptFile = paramList[3]

	output = open(ctFile, 'rb').read()

	ct, cipherKey_paddedIV_messageDigest_cipherKeyLength, signedMessage_tag = output.split(firstName)

	cipherKey_paddedIV, messageDigest_cipherKeyLength = cipherKey_paddedIV_messageDigest_cipherKeyLength.split(lastName)

	messageDigest = messageDigest_cipherKeyLength[0:64]

	cipherKeyLength = base64.b64decode(messageDigest_cipherKeyLength[64:])

	cipherKey = cipherKey_paddedIV[0:int(cipherKeyLength)]

	paddedIV = cipherKey_paddedIV[int(cipherKeyLength):]

	signedMessage, tag = signedMessage_tag.split(lastName) 

	fullMessage = ct + cipherKey + paddedIV + messageDigest

	if messageVerification(sendPubKey, fullMessage, signedMessage) == False:
		sys.exit("Signature verification failed, try again!")
            
	key = RSADecryption(destPriKey, cipherKey)

	hashVerification = HASHFunction(ct+cipherKey, key)

        if hashVerification != messageDigest:
            sys.exit("Hash values do not match.")

	iv = dataUnpadding(paddedIV)

	pt = AESDecryption(key, associatedData, iv, tag, ct)

	outputFile = open(ptFile, "wb")

	outputFile.write(pt)

	outputFile.close() 

def main():

	# Retrieve parameter list for encryption/decryption operation from command-line

	firstName = base64.b64decode('z4DPhc+BzrHPgA====') 	#πυραπ
	lastName = base64.b64decode('zrLOt86xz4TOuc6x==')  	#βηατια

	associatedData = firstName+lastName
	
	paramList, operation  = argsParser()
	
	if operation == 'e':
		Encryption(paramList, operation, firstName, lastName, associatedData)


	elif operation == 'd':
		Decryption(paramList, operation, firstName, lastName, associatedData)

	else:
		sys.exit("Invalid operation parameter, try again.")

	
if __name__ == "__main__":
    main()

