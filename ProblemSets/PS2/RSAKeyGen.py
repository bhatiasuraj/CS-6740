import os

key = raw_input('Enter the Type of key (pem/der):')
bits = raw_input('Enter Key Size (1024/2048/3072/4096):')


if key == 'pem':
    os.system('openssl genrsa -out senderprivate.pem '+bits)
    os.system('openssl rsa -in senderprivate.pem -pubout > senderpublic.pem')

    os.system('openssl genrsa -out receiverprivate.pem '+bits)
    os.system('openssl rsa -in receiverprivate.pem -pubout > receiverpublic.pem')

elif key == 'der':
    os.system('openssl genrsa -out senderprivate.pem '+bits)
    os.system('openssl pkcs8 -topk8 -inform PEM -outform DER -in senderprivate.pem -out senderprivate.der -nocrypt')
    os.system('openssl rsa -in senderprivate.pem -pubout -outform DER -out senderpublic.der')
    os.system('rm senderprivate.pem')

    os.system('openssl genrsa -out receiverprivate.pem '+bits)
    os.system('openssl pkcs8 -topk8 -inform PEM -outform DER -in receiverprivate.pem -out receiverprivate.der -nocrypt')
    os.system('openssl rsa -in receiverprivate.pem -pubout -outform DER -out receiverpublic.der')
    os.system('rm receiverprivate.pem')
else:
    exit('Key type not supported! :(')
