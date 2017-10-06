#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)

#python fcrypt.py -e destinationPublicKey.der senderPrivateKey.der inputPlainFile.txt outputCipherFile.txt
#python fcrypt.py -d destinationPrivateKey.der senderPublicKey.der outputCipherFile.txt outputPlainFile.txt

python fcrypt.py -e destinationPublicKey.pem senderPrivateKey.pem inputPlainFile.txt outputCipherFile.txt
python fcrypt.py -d destinationPrivateKey.pem senderPublicKey.pem outputCipherFile.txt outputPlainFile.txt

if ! diff -q inputPlainFile.txt outputPlainFile.txt > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi
