import base64
import socket
import time
import json
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def client_program():
    host = socket.gethostname()
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))
    authenticator_public_key = client_socket.recv(1024)
    key = RSA.importKey(authenticator_public_key)
    cipher = PKCS1_OAEP.new(key)

    username = input("Username: ")
    password = input("Password: ")
    message = username + ":" + password

    encrypted_credentials = cipher.encrypt(message.encode())
    client_socket.send(encrypted_credentials)
    time.sleep(1)

    data = client_socket.recv(1024).decode()
    zero = 0
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=zero.to_bytes(1, 'big'),
        iterations=480000,
    )
    clientkey = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(clientkey)
    decryptedmessage = f.decrypt(data).decode()
    decryptedJSON = json.loads(decryptedmessage)
    status = decryptedJSON['auth']
    token = decryptedJSON['token']
    client_socket.close()
    if status == "fail":
        print("Failed login")
    else:
       host = socket.gethostname()
       port = 5001

       client_socket = socket.socket()
       client_socket.connect((host, port))
       client_socket.send(token.encode())
       client_socket.close()


if __name__ == '__main__':
    client_program()