import base64
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def server_program():
    host = socket.gethostname()
    port = 5001
    authAppSymmetricKey = b"MySecretKey"


    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))
    encrypted_token = conn.recv(1024).decode()
    zero = 0
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=zero.to_bytes(1, 'big'),
        iterations=480000,
    )
    clientkey = base64.urlsafe_b64encode(kdf.derive(authAppSymmetricKey))
    f = Fernet(clientkey)
    token = f.decrypt(encrypted_token).decode()

    print(token)
    conn.close()


if __name__ == '__main__':
    server_program()
