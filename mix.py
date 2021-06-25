# Matan Saloniko, 318570769, Idan Givati, 315902239

import sys
import socket
import time
import threading
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Getting the current server's port from the ips.txt file
def getPort():
    ipFile = open("ips.txt", "r")
    ips = ipFile.readlines()
    ipFile.close()
    myDetails = ips[int(sys.argv[1]) - 1]
    port = myDetails.split(' ')[1]
    if port[-1] == '\n':
        port = port[:-1]
    return int(port)

#Getting the server's private key from the pem file.
def getPrivateKey():
    pemName = "sk" + sys.argv[1] + ".pem"
    with open(pemName, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

#Getting the destination IP from the decrypted message.
def getDestIP(decryptedText):
    ip = ""
    for seg in decryptedText[0:4]:
        ip = ip + str(int(seg)) + "."
    ip = ip[:-1]
    return ip

#Getting the destination port from the decrypted message.
def getDestPort(decryptedText):
    return int.from_bytes(decryptedText[4:6], byteorder='big')

#Activating the server
def activateServer(myPort, myPrivateKey, messages):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', myPort))
    server.listen(3000)
    BUFFER_SIZE = 4096

    #Listening indefinetly.
    while True:
        client_socket, client_addr = server.accept()
        data = client_socket.recv(BUFFER_SIZE)
        #Decrypting the message.
        decryptedText = myPrivateKey.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #Adding the message to the array
        destIP = getDestIP(decryptedText)
        destPort = getDestPort(decryptedText)
        destMessage = decryptedText[6:]
        messages.append(((destIP, destPort, destMessage)))
        client_socket.close()


#Sending the messages in that round.
def sendToDest(messages):
    length = len(messages)
    maxRand = length - 1
    #Sending a random message each time and removing the message sent.
    for i in range(length):
        rand = random.randint(0, maxRand)
        maxRand = maxRand - 1
        message = messages[rand]
        del messages[rand]
        ip = message[0]
        port = message[1]
        content = message[2]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            s.send(content)
            s.close()
        except ConnectionError:
            print("Could not establish connection")

def main():
    if len(sys.argv) == 1:
        print("Not enough parameters")
        return
    #Getting the server's details
    myPort = getPort()
    myPrivateKey = getPrivateKey()
    messages = []
    #Sending the server to a different thread.
    serverThread = threading.Thread(target=activateServer, args=(myPort, myPrivateKey, messages,))
    serverThread.start()
    while True:
        #Sending all messages and waiting for the next round.
        sendThread = threading.Thread(target=sendToDest, args=(messages,))
        sendThread.start()
        time.sleep(60)

if __name__ == "__main__":
    main()
