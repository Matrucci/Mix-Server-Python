# Matan Saloniko, 318570769, Idan Givati, 315902239

import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
    ipByte = buildIP(message[5])
    portByte = int(message[6]).to_bytes(2, 'big')
    encryptedMessage = ipByte + portByte + encryptedMessage
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
    for i in servers:
        pemName = "pk" + i + ".pem"
        pemFile = open(pemName, "r")
        pem = pemFile.read()
        pemFile.close()
        key = load_pem_public_key(pem.encode(), default_backend())
        
    
    
    
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
        buildMessage(message)

    

if __name__ == "__main__":
    main()
