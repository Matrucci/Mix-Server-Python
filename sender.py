# Matan Saloniko, 318570769, Idan Givati, 315902239

import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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

def buildMessage(message):
    semetricKey = createSemetricKey(message[3], message[4])
    messageData = message[0]
    encryptedMessage = semetricKey.encrypt(messageData.encode())
    

def main():
    if len(sys.argv) == 1:
        return
    x = sys.argv[1]
    messageFile = "messages" + x + ".txt"
    file = open(messageFile, "r")
    messages = file.readlines()
    for message in messages:
        buildMessage(message)

    

if __name__ == "__main__":
    main()
