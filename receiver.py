# Matan Saloniko, 318570769, Idan Givati, 315902239

import sys
import base64
import socket
import time
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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

#Receiving data from given port
#Prints the messages after decryption and adds the current time.
def startReceiving(port, semetricKey):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0',port))
    s.listen(3000)
    BUFFER_SIZE = 4096

    while True:
        client_socket, client_addr = s.accept()
        data = client_socket.recv(BUFFER_SIZE)

        decryptedMessage = semetricKey.decrypt(data).decode("UTF-8")

        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print(decryptedMessage + " " + current_time)
        client_socket.close()

#Main function.
def main():
    if len(sys.argv) != 4:
        print("Not enough parameters")
        return
    password = sys.argv[1].encode()
    salt = sys.argv[2].encode()
    port = int(sys.argv[3])
    #Getting semetric key by password and salt.
    semetricKey = createSemetricKey(password, salt)
    #Listening indefinitely.
    startReceiving(port, semetricKey)


if __name__ == "__main__":
    main()
