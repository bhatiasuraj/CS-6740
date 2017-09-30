#!/usr/bin/python

'''

Author: Suraj Bhatia

Title: fcrypt.py

Description: 

Usage: python fcrypt.py -e destination_public_key_filename sender_private_key_filename input_plaintext_file ciphertext_file

       python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file

'''

from socket import *
import argparse
import sys

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

	# Retrieve username, server port and IP from command-line
	
	paramList, operation  = argsParser()
	
	if operation = "e":
		destPubKeyFile = paramList[0]
		sendPriKeyFile = paramList[1]
		ipPlainText = paramList[2]
		cipherFile = paramList[3]

	if operation = "d":
		destPriKeyFile = paramList[0]
		sendPubKeyFile = paramList[1]
		cipherFile = paramList[2]
		opPlainText = paramList[3]

if __name__ == "__main__":
    main()

