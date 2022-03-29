import socket
from Crypto.PublicKey import RSA
import base64
import pickle
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from hashlib import sha512
from AESauth import *
from Crypto.Random import get_random_bytes

#socket variables
HOST = "127.0.0.1"
PORT = 65432
PASSWORD = b"P0"

# AES variables
AES_key_length = 16
secret_key = os.urandom(AES_key_length)
encoded_secret_key = base64.b64encode(secret_key)


# RSA variables
random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()
sentinel = get_random_bytes(16)

encrypt_str = "encrypted_message="


# create a server object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockObj:
    sockObj.bind((HOST, PORT))
    sockObj.listen() #listen to ant client connection
    clientConn, addr = sockObj.accept() # accept/ handshake with client
    with clientConn:
        print(f"Connection from {addr} has been established!")
        while True:
            clientData = str(clientConn.recv(1024).decode()) # recieve message from client
            clientData = clientData.replace("\r\n", '')

            if clientData == 'Client:OK': # on confirmation of msg recival
                pubKey = b"public_key="+public_key.export_key() + b"\n" # send public key to the client
                clientConn.send(pubKey)
                print("Public key sent to client.")

            elif encrypt_str in clientData: # recieve encrypted data
                data = clientData.replace(encrypt_str,'') # format encrypted data
                encrypted = eval(data)
                cipher = PKCS1_v1_5.new(private_key)
                decrypted = cipher.decrypt(encrypted, sentinel) # decrypt using private key
                if str(decrypted) == str(PASSWORD): #verify password
                    print('Password verified')
                    hash = int.from_bytes(sha512(encoded_secret_key).digest(), byteorder='big')
                    signature = pow(hash, private_key.d, private_key.n)
                    Aes_list = [encoded_secret_key, signature] # send AES key and AES+signature
                    AES_obj = pickle.dumps(Aes_list)
                    print('Sending AES key and signature of AESkey to client')
                    clientConn.send(AES_obj)# send AES key and AES+signature
                    AES_encrypt_msg = clientConn.recv(4096) # Recieve encrypted AES message
                    AES_encrypt_msg = pickle.loads(AES_encrypt_msg)
                    AES_decrypt_msg = decrypt_AES_GCM(AES_encrypt_msg, encoded_secret_key) #Recieve encrypted AES message
                    if AES_decrypt_msg == b"hello": # verify message
                        print("AES key encrypted hello (to client)")
                        AES_server_msg = encrypt_AES_GCM(b"hello to you too", encoded_secret_key) #send AES encrypted response
                        AES_server_msg = pickle.dumps(AES_server_msg)
                        clientConn.sendall(AES_server_msg)


            elif clientData == "Quit":
                break


