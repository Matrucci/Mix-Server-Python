# Matan Saloniko, 318570769, Idan Givati, 315902239

import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def createSemetricKey(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    return f

def buildIP(ip):
    ipSplit = ip.split('.')
    ipB = b''
    for seg in ipSplit:
        ipB += int(seg).to_bytes(1, 'big')
    return ipB

def buildMessage(messageLine):
    message = messageLine.split(' ')
    semetricKey = createSemetricKey(message[3], message[4])
    messageData = message[0]
    encryptedMessage = semetricKey.encrypt(messageData.encode())
    print(encryptedMessage)
    ipByte = buildIP(message[5])
    portByte = int(message[6]).to_bytes(2, 'big')
    encryptedMessage = ipByte + portByte + encryptedMessage
    print(encryptedMessage)
    servers = message[1].split(',')
    servers.reverse()
    serversDetails = []
    ipsFile = open("ips.txt", "r")
    ipsTxt = ipsFile.readlines()
    ipsFile.close()
    try:
        for i in servers:
            serversDetails.append(ipsTxt[int(i) - 1])
    except:
        print("Wrong server number")
    position = 0
    for i in servers:
        pemName = "pk" + i + ".pem"
        with open(pemName, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        encryptedMessage = public_key.encrypt(
            encryptedMessage,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
            )
        )
        if position != len(servers) - 1:
            serverIpBytes = buildIP(serversDetails[position].split(' ')[0])
            serverPortBytes = int(serversDetails[position].split(' ')[1][:-1]).to_bytes(2, 'big')
            encryptedMessage = serverIpBytes + serverPortBytes + encryptedMessage
        position = position + 1
    returnItems = [serversDetails[len(serversDetails) - 1].split(' ')[0], serversDetails[len(serversDetails) - 1].split(' ')[1][:-1], encryptedMessage]
    return returnItems
    
    """
    position = 1
    for ip in ipsTxt:
        if str(position) in servers:
            serversDetails.append(ip)
        position = position + 1
    
    for i in range(len(servers) - 1, -1, -1):
        print(servers[i] + ", " + serversDetails[len(serversDetails) - i - 1])
    """
    


def main():
    if len(sys.argv) == 1:
        return
    x = sys.argv[1]
    messageFile = "messages" + x + ".txt"
    file = open(messageFile, "r")
    messages = file.readlines()
    file.close()
    for message in messages:
        messageParams = buildMessage(message)
        #print(messageParams)

    

if __name__ == "__main__":
    main()
