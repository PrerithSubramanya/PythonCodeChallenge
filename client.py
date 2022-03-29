import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from hashlib import sha512
from AESauth import *

#socket variables
HOST = "127.0.0.1"
PORT = 65432
PASSWORD = "P0"


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sockObj:
    sockObj.connect((HOST, PORT)) #connect to client
    msg = "Client:OK"
    sockObj.sendall(msg.encode()) # veryify connection
    server_string = str(sockObj.recv(1024).decode())
    server_string = server_string.replace("public_key=", '')# get public key to encrypt message
    server_string = server_string.replace("\r\n", '')
    server_public_key = RSA.importKey(server_string)
    cipher = PKCS1_v1_5.new(server_public_key)
    message = b"P0"
    encrypted = cipher.encrypt(message)
    Pass = "encrypted_message="+str(encrypted) # encrypt password using public key
    print("Public key encrypted clientpass")
    sockObj.sendall(Pass.encode()) # send password

    server_response = sockObj.recv(1024) # recieve AESkey and signature
    Aes_obj = pickle.loads(server_response)
    aes_key = Aes_obj[0]
    signedAes = Aes_obj[1]
    hash = int.from_bytes(sha512(aes_key).digest(), byteorder='big')
    hashFromSignature = pow(signedAes, server_public_key.e, server_public_key.n)
    if hash == hashFromSignature: # verify AES key and signature
        print("AES key verified (from server)")
        AES_encrpyt_msg = encrypt_AES_GCM(b"hello", aes_key)# send AES encrypted message
        AES_encrpyt_msg = pickle.dumps(AES_encrpyt_msg)
        sockObj.sendall(AES_encrpyt_msg)
        server_response = sockObj.recv(1024)
        AES_server_msg = pickle.loads(server_response)
        AES_server_msg = decrypt_AES_GCM(AES_server_msg, aes_key) # recieve AES encrypted message
        if AES_server_msg == b"hello to you too":
            print("AES key encrypted hello to you too (from server)")





