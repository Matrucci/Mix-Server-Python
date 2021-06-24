# Matan Saloniko, 318570769, Idan Givati, 315902239


import sys
import base64
import socket
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def getPort():
    ipFile = open("ips.txt", "r")
    ips = ipFile.readlines()
    ipFile.close()
    myDetails = ips[int(sys.argv[1]) - 1]
    port = myDetails.split(' ')[1]
    if port[-1] == '\n':
        port = port[:-1]
    return int(port)

def getPrivateKey():
    pemName = "sk" + sys.argv[1] + ".pem"
    with open(pemName, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

def getDestIP(decryptedText):
    ip = ""
    for seg in decryptedText[0:4]:
        ip = ip + str(int(seg)) + "."
    ip = ip[:-1]
    return ip

def getDestPort(decryptedText):
    return int.from_bytes(decryptedText[4:6], byteorder='big')


def activateServer(myPort, myPrivateKey):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', myPort))
    server.listen(3000)
    BUFFER_SIZE = 4096
    messages = []

    while True:
        client_socket, client_addr = server.accept()
        data = client_socket.recv(BUFFER_SIZE)
        decryptedText = myPrivateKey.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.sHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        destIP = getDestIP(decryptedText)
        destPort = getDestPort(decryptedText)
        destMessage = decryptedText[6:]
        messages.append(((destIP, destPort, destMessage)))
        client_socket.close()


def main():
    if len(sys.argv) == 1:
        print("Not enough parameters")
        return
    myPort = getPort()
    myPrivateKey = getPrivateKey()
    activateServer(myPort, myPrivateKey)

if __name__ == "__main__":
    main()
