#!/bin/bash

# Simple test for fcrypt.py (CS 4740/6740: Network Security)

> outputPlainFile.txt

python fcrypt.py -e destinationPublicKey.der senderPrivateKey.der inputPlainFile.txt outputCipherFile.txt
python fcrypt.py -d destinationPrivateKey.der senderPublicKey.der outputCipherFile.txt outputPlainFile.txt

#python fcrypt.py -e destinationPublicKey.pem senderPrivateKey.pem inputPlainFile.txt outputCipherFile.txt
#python fcrypt.py -d destinationPrivateKey.pem senderPublicKey.pem outputCipherFile.txt outputPlainFile.txt

if [ $? -eq 0 ]; then

	if ! diff -q inputPlainFile.txt outputPlainFile.txt > /dev/null; then
  		echo "FAIL"
  	else echo "PASS!"

	fi
else
	echo "FAIL"

fi

