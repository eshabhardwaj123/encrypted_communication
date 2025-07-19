

import socket, pickle, threading
from tkinter import *
from crypto_utils import generate_keys, generate_shared_key, encrypt_message, decrypt_message

HOST = 'localhost'
PORT = 65432

private_key, public_key = generate_keys()

class SecureServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(" Secure Server Chat")

        self.chat_box = Text(root, height=20, width=60, state=DISABLED, bg="#f0f0f0")
        self.chat_box.pack(padx=10, pady=5)

        self.entry = Entry(root, width=40)
        self.entry.pack(side=LEFT, padx=(10, 0), pady=5)

        self.send_btn = Button(root, text="Send", command=self.send_message)
        self.send_btn.pack(side=LEFT, padx=5)

        self.conn = None
        self.shared_key = None

        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            self.update_chat(" Waiting for connection...")
            self.conn, addr = s.accept()
            self.update_chat(f" Connected by {addr}")

            with self.conn:
                # Key exchange
                self.conn.sendall(pickle.dumps(public_key))
                client_public_key = pickle.loads(self.conn.recv(4096))
                self.shared_key = generate_shared_key(private_key, client_public_key)
                self.update_chat(" Secure AES channel established.")

                while True:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    decrypted = decrypt_message(self.shared_key, data)
                    self.update_chat(f"Client: {decrypted}")

    def send_message(self):
        msg = self.entry.get()
        if msg and self.conn:
           if self.shared_key is None:
            self.update_chat(" Cannot send message: No shared key established.")
            return
        encrypted = encrypt_message(self.shared_key, msg)
        self.conn.sendall(encrypted)
        self.update_chat(f"You: {msg}")
        self.entry.delete(0, END)

    def update_chat(self, message):
        self.chat_box.config(state=NORMAL)
        self.chat_box.insert(END, message + "\n")
        self.chat_box.config(state=DISABLED)
        self.chat_box.see(END)

root = Tk()
gui = SecureServerGUI(root)
root.mainloop()
