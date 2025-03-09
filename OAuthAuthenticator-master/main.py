import base64
import socket

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def server_program():
    host = socket.gethostname()
    port = 5000
    authAppSymmetricKey = b"MySecretKey"

    key_pair = RSA.generate(2048)

    public_key = key_pair.publickey().exportKey()
    private_key = key_pair
    cipher = PKCS1_OAEP.new(private_key)

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(1)
    conn, address = server_socket.accept()
    print("Connection from: " + str(address))
    conn.send(public_key)
    encrypted_credentials = conn.recv(1024)
    decrypted_credentials = cipher.decrypt(encrypted_credentials).decode()

    credentials = decrypted_credentials.split(":")
    #dataString = 'grant_type=password&client_id=TestClient&username=' + credentials[0] + '&password=' + credentials[1]
    #print(dataString)
    #r = requests.put("https://api.mysite.com/token", data=dataString)
    r = "test JSON"

    zero = 0
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt= zero.to_bytes(1, 'big'),
        iterations=480000,
    )
    appkey = base64.urlsafe_b64encode(kdf.derive(authAppSymmetricKey))
    f = Fernet(appkey)
    encryptedJSON = f.encrypt(r.encode())
    clientMessage = '{"auth":"success", "token":"' + encryptedJSON.decode() + '"}'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=zero.to_bytes(1, 'big'),
        iterations=480000,
    )
    clientkey = base64.urlsafe_b64encode(kdf.derive(credentials[1].encode()))
    f = Fernet(clientkey)
    encryptedclientmessage = f.encrypt(clientMessage.encode())
    conn.send(encryptedclientmessage)

    conn.close()


if __name__ == '__main__':
    server_program()
