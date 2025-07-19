# secure_client_gui.py

import socket, pickle, threading
from tkinter import *
from crypto_utils import generate_keys, generate_shared_key, encrypt_message, decrypt_message

HOST = 'localhost'
PORT = 65432

private_key, public_key = generate_keys()

class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Client Chat")

        self.chat_box = Text(root, height=20, width=60, state=DISABLED, bg="#e8f8f5")
        self.chat_box.pack(padx=10, pady=5)

        self.entry = Entry(root, width=40)
        self.entry.pack(side=LEFT, padx=(10, 0), pady=5)

        self.send_btn = Button(root, text="Send", command=self.send_message)
        self.send_btn.pack(side=LEFT, padx=5)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None

        threading.Thread(target=self.start_client, daemon=True).start()

    def start_client(self):
        self.sock.connect((HOST, PORT))
        self.update_chat("🔗 Connected to server.")

        server_public_key = pickle.loads(self.sock.recv(4096))
        self.sock.sendall(pickle.dumps(public_key))

        self.shared_key = generate_shared_key(private_key, server_public_key)
        self.update_chat("🔐 Secure AES channel established.")

        while True:
            data = self.sock.recv(4096)
            if not data:
                break
            decrypted = decrypt_message(self.shared_key, data)
            self.update_chat(f"Server: {decrypted}")

    def send_message(self):
        msg = self.entry.get()
        if msg:
            encrypted = encrypt_message(self.shared_key, msg)
            self.sock.sendall(encrypted)
            self.update_chat(f"You: {msg}")
            self.entry.delete(0, END)

    def update_chat(self, message):
        self.chat_box.config(state=NORMAL)
        self.chat_box.insert(END, message + "\n")
        self.chat_box.config(state=DISABLED)
        self.chat_box.see(END)

root = Tk()
gui = SecureClientGUI(root)
root.mainloop()
