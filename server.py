import socket
import threading
from crypto_utils import generate_keys, derive_shared_key, encrypt_message_aes, decrypt_message_aes, serialize_public_key, deserialize_public_key

HOST = '127.0.0.1'
PORT = 65432

private_key, public_key = generate_keys()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)
print("[SERVER] Waiting for connection...")

conn, addr = server.accept()
print(f"[CONNECTED] {addr}")

# Exchange public keys
conn.sendall(serialize_public_key(public_key))
client_pub_key_bytes = conn.recv(1024)
client_pub_key = deserialize_public_key(client_pub_key_bytes)

# Derive AES key
shared_key = derive_shared_key(private_key, client_pub_key)

def receive_messages():
    while True:
        try:
            encrypted_data = conn.recv(1024 + 12)  # 12 bytes nonce + ciphertext
            decrypted = decrypt_message_aes(shared_key, encrypted_data)
            print(f"[CLIENT]: {decrypted}")
        except Exception as e:
            print("[ERROR RECEIVING]", e)
            break

def send_messages():
    while True:
        msg = input("[YOU]: ")
        encrypted_data = encrypt_message_aes(shared_key, msg)
        conn.sendall(encrypted_data)

recv_thread = threading.Thread(target=receive_messages)
recv_thread.start()
send_messages()

