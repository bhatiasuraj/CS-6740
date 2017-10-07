(rm *.txt) 2> /dev/null;
(rm *.pem || rm *.der) 2> /dev/null;
touch inputPlainFile.txt
touch outputPlainFile.txt
touch outputCipherFile.txt
