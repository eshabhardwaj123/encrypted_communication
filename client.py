import socket
import threading
from crypto_utils import generate_key_pair, derive_shared_key, encrypt_message_aes, decrypt_message_aes, serialize_pub_key, deserialize_pub_key

HOST = '127.0.0.1'
PORT = 65432

private_key, public_key = generate_key_pair()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("[CLIENT] Connected to server.")

# Exchange public keys
server_pub_key_bytes = client.recv(1024)
client.sendall(serialize_pub_key(public_key))
server_pub_key = deserialize_pub_key(server_pub_key_bytes)

# Derive AES key
shared_key = derive_shared_key(private_key, server_pub_key)

def receive_messages():
    while True:
        try:
            nonce = client.recv(12)
            tag = client.recv(16)
            ciphertext = client.recv(1024)
            decrypted = decrypt_message_aes(shared_key, nonce, ciphertext, tag)
            print(f"[SERVER]: {decrypted}")
        except Exception as e:
            print("[ERROR RECEIVING]", e)
            break

def send_messages():
    while True:
        msg = input("[YOU]: ")
        nonce, ciphertext, tag = encrypt_message_aes(shared_key, msg)
        client.sendall(nonce)
        client.sendall(tag)
        client.sendall(ciphertext)

recv_thread = threading.Thread(target=receive_messages)
recv_thread.start()
send_messages()
