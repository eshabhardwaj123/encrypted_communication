import socket
import threading
from crypto_utils import generate_keys, derive_shared_key, encrypt_message_aes, decrypt_message_aes, serialize_public_key, deserialize_public_key

HOST = '127.0.0.1'
PORT = 65432

private_key, public_key = generate_keys()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("[CLIENT] Connected to server.")

# Exchange public keys
server_pub_key_bytes = client.recv(1024)
client.sendall(serialize_public_key(public_key))
server_pub_key = deserialize_public_key(server_pub_key_bytes)

# Derive AES key
shared_key = derive_shared_key(private_key, server_pub_key)

def receive_messages():
    while True:
        try:
            encrypted_data = client.recv(1024 + 12)
            decrypted = decrypt_message_aes(shared_key, encrypted_data)
            print(f"[SERVER]: {decrypted}")
        except Exception as e:
            print("[ERROR RECEIVING]", e)
            break

def send_messages():
    while True:
        msg = input("[YOU]: ")
        encrypted_data = encrypt_message_aes(shared_key, msg)
        client.sendall(encrypted_data)

recv_thread = threading.Thread(target=receive_messages)
recv_thread.start()
send_messages()
