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
from queue import PriorityQueue

#Creating semetric key for encryption.
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

#Taking IP string and turning it into bytes representation.
def buildIP(ip):
    ipSplit = ip.split('.')
    ipB = b''
    for seg in ipSplit:
        ipB += int(seg).to_bytes(1, 'big')
    return ipB

#Taking the line from the file and turning it into a message for the server.
def buildMessage(messageLine):
    message = messageLine.split(' ')
    #Creating semetric key by password and salt.
    semetricKey = createSemetricKey(message[3], message[4])
    messageData = message[0]
    #Encrypting the original message with the semetric key.
    encryptedMessage = semetricKey.encrypt(messageData.encode())
    ipByte = buildIP(message[5])
    #Remove the \n before continueing. 
    if message[6][-1] == '\n':
        message[6] = message[6][:-1]
    portByte = int(message[6]).to_bytes(2, 'big')
    #Adding the IP and port
    encryptedMessage = ipByte + portByte + encryptedMessage
    servers = message[1].split(',')
    servers.reverse()
    serversDetails = []
    ipsFile = open("ips.txt", "r")
    ipsTxt = ipsFile.readlines()
    ipsFile.close()
    #Getting the IP and port of the servers.
    try:
        for i in servers:
            serversDetails.append(ipsTxt[int(i) - 1])
    except:
        print("Wrong server number")
    #Using the server's public key to encrypt the message
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
        #Adding the server's IP and port
        serverDetailsSplit = serversDetails[position].split(' ')
        if serverDetailsSplit[1][-1] == '\n':
            serverDetailsSplit[1] = serverDetailsSplit[1][:-1]
        if position != len(servers) - 1:
            serverIpBytes = buildIP(serverDetailsSplit[0])
            serverPortBytes = int(serverDetailsSplit[1]).to_bytes(2, 'big')
            encryptedMessage = serverIpBytes + serverPortBytes + encryptedMessage
        position = position + 1
    #Returning the IP and port of the last server we need to send to and the message.
    returnItems = [serverDetailsSplit[0], serverDetailsSplit[1], encryptedMessage]
    return returnItems

#Sending a message to a server by IP and port.
#Taking into account the round number the message should be sent in.
def sendQueueToServer(messageQueue):
    position = 0
    while not messageQueue.empty():
        item = messageQueue.get()
        if item[0] > position:
            time.sleep(60 * (item[0] - position))
            position = item[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((item[1][0], int(item[1][1])))
            s.send(item[1][2])
            s.close()
        except ConnectionError:
            print("There was a problem connecting to server")

def main():
    if len(sys.argv) == 1:
        return
    x = sys.argv[1]
    #Waiting a few seconds so the server would start before the program starts.
    time.sleep(5)
    #Opening the messages file.
    messageFile = "messages" + x + ".txt"
    file = open(messageFile, "r")
    messages = file.readlines()
    file.close()
    messageQueue = PriorityQueue()
    #Building every message and sending to the server.
    for message in messages:
        messageParams = buildMessage(message)
        messageQueue.put((int(message.split(' ')[2]), messageParams))
    sendQueueToServer(messageQueue)
        #sendToServer(messageParams[0], messageParams[1], messageParams[2])

    

if __name__ == "__main__":
    main()
