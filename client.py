import customtkinter as ctk
import threading
import socket
import os
import struct
from tkinter import END, filedialog
from crypto_utils import generate_keys, derive_shared_key, aes_encrypt, aes_decrypt, deserialize_public_key
from cryptography.hazmat.primitives import serialization

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

HOST = '127.0.0.1'
PORT = 65432

# Generate client's key pair
private_key, public_key = generate_keys()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client.connect((HOST, PORT))
    print(f"[CLIENT] Connected to server at {HOST}:{PORT}")
except ConnectionRefusedError:
    print("[CLIENT ERROR] Connection refused. Make sure the server is running.")
    exit()

# --- Key Exchange Phase ---
try:
    # Send client's public key to server (PEM format)
    client.send(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Receive server's public key (PEM format)
    server_pub_key_bytes = client.recv(1024)
    if not server_pub_key_bytes:
        raise Exception("Server did not send public key during handshake.")

    # Deserialize the server's public key
    server_pub_key = deserialize_public_key(server_pub_key_bytes)

    # Derive the shared AES key
    shared_key = derive_shared_key(private_key, server_pub_key)
    print("[CLIENT] Secure channel established with server.")

except Exception as e:
    print(f"[CLIENT ERROR] Key exchange failed: {e}")
    client.close()
    exit()


class ChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Client - Secure Chat")
        self.geometry("600x650")
        self.resizable(False, False)

        self.current_theme = "dark"
        self.authenticated = False # New state variable for authentication status

        # --- Login Frame Setup ---
        self.login_frame = ctk.CTkFrame(self)
        self.login_frame.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(self.login_frame, text="Secure Chat Login", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=20)

        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Username", width=250)
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Password", show="*", width=250)
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.attempt_login, width=250)
        self.login_button.pack(pady=20)

        self.login_status_label = ctk.CTkLabel(self.login_frame, text="", text_color="red")
        self.login_status_label.pack(pady=5)

        # --- Main Chat UI Components (initially hidden/disabled) ---
        self.theme_button = ctk.CTkButton(self, text="Toggle Theme", command=self.toggle_theme)
        # self.theme_button.pack(pady=5) # Will be packed after login

        self.chat_frame = ctk.CTkScrollableFrame(self, width=560, height=440)
        # self.chat_frame.pack(pady=10, padx=20) # Will be packed after login

        self.typing_label = ctk.CTkLabel(self, text="", text_color="grey")
        # self.typing_label.pack() # Will be packed after login

        self.entry_frame = ctk.CTkFrame(self)
        # self.entry_frame.pack(pady=10, padx=20, fill="x") # Will be packed after login

        self.msg_entry = ctk.CTkEntry(self.entry_frame, width=350, placeholder_text="Type a message...")
        self.msg_entry.pack(side="left", padx=(10, 5), pady=10)
        self.msg_entry.bind("<KeyRelease>", self.on_typing)

        self.emoji_button = ctk.CTkButton(self.entry_frame, text="😀", width=30, command=self.toggle_emoji_picker,
                                          font=ctk.CTkFont(size=18))
        self.emoji_button.pack(side="left", padx=5)

        self.file_button = ctk.CTkButton(self.entry_frame, text="📄", width=30, command=self.send_file,
                                         font=ctk.CTkFont(size=18))
        self.file_button.pack(side="left", padx=5)

        self.send_button = ctk.CTkButton(self.entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left", padx=5)

        self.emoji_frame = None
        self.is_typing = False
        self.typing_timer = None

        # Start thread for receiving messages from the server
        threading.Thread(target=self.receive_messages, daemon=True).start()

        self._apply_theme_colors() # Apply initial theme colors to login frame too

    def _toggle_chat_ui(self, enable: bool):
        """Helper to enable/disable chat UI elements."""
        if enable:
            self.login_frame.pack_forget() # Hide login frame
            self.theme_button.pack(pady=5)
            self.chat_frame.pack(pady=10, padx=20)
            self.typing_label.pack()
            self.entry_frame.pack(pady=10, padx=20, fill="x")
        else:
            self.theme_button.pack_forget()
            self.chat_frame.pack_forget()
            self.typing_label.pack_forget()
            self.entry_frame.pack_forget()
            self.login_frame.pack(expand=True, fill="both", padx=20, pady=20) # Show login frame

        # Enable/disable widgets within the chat UI
        for widget in [self.msg_entry, self.emoji_button, self.file_button, self.send_button]:
            widget.configure(state="normal" if enable else "disabled")


    def attempt_login(self):
        """Attempts to send login credentials to the server."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.login_status_label.configure(text="Please enter username and password.")
            return

        self.login_status_label.configure(text="Attempting login...")
        self.login_button.configure(state="disabled") # Disable button during login attempt

        try:
            # Construct authentication payload: b'AUTH' + username||password
            auth_payload = b'AUTH' + username.encode('utf-8') + b'||' + password.encode('utf-8')
            encrypted_auth_payload = aes_encrypt(shared_key, auth_payload)
            payload_length = len(encrypted_auth_payload)

            client.send(struct.pack('!I', payload_length))
            client.sendall(encrypted_auth_payload)
            print("[CLIENT] Sent authentication request.")

        except Exception as e:
            self.login_status_label.configure(text=f"Login error: {e}")
            self.login_button.configure(state="normal")
            print(f"[CLIENT ERROR] Sending authentication: {e}")


    def _apply_theme_colors(self):
        """Applies colors based on the current theme."""
        if self.current_theme == "dark":
            self.configure(fg_color="#2b2b2b")
            self.login_frame.configure(fg_color="#2b2b2b") # Apply to login frame too
            self.chat_frame.configure(fg_color="#2b2b2b")
            self.entry_frame.configure(fg_color="#2b2b2b")
            self.typing_label.configure(text_color="grey")
        else: # Light theme
            self.configure(fg_color="white")
            self.login_frame.configure(fg_color="white") # Apply to login frame too
            self.chat_frame.configure(fg_color="white")
            self.entry_frame.configure(fg_color="white")
            self.typing_label.configure(text_color="grey")

        # Redraw existing messages with new colors
        for widget in self.chat_frame.winfo_children():
            if isinstance(widget, ctk.CTkLabel):
                message = widget.cget("text")
                is_sent = widget.cget("anchor") == "e"
                widget.destroy()
                self.display_message(message, is_sent=is_sent)


    def toggle_theme(self):
        """Toggles between dark and light themes."""
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.current_theme = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.current_theme = "dark"
        self._apply_theme_colors()

    def display_message(self, message, is_sent=False):
        """
        Displays a message in the chat frame with theme-specific colors.
        Args:
            message (str): The message text to display.
            is_sent (bool): True if the message was sent by this client, False otherwise.
        """
        align = "e" if is_sent else "w"
        if self.current_theme == "dark":
            bubble_color = "#1f538d" if is_sent else "#3a3a3a"
            text_color = "lightgreen" if is_sent else "white"
        else: # Light theme
            bubble_color = "#ADD8E6" if is_sent else "#E0E0E0"
            text_color = "black"
        label = ctk.CTkLabel(self.chat_frame, text=message, text_color=text_color,
                             fg_color=bubble_color, corner_radius=10,
                             anchor="w", justify="left", wraplength=480)
        label.pack(anchor=align, padx=10, pady=5)
        self.chat_frame._parent_canvas.yview_moveto(1.0)


    def send_message(self):
        """
        Sends a text message typed in the entry field to the server.
        Only allowed if authenticated.
        """
        if not self.authenticated:
            self.login_status_label.configure(text="Please log in first.")
            return

        msg = self.msg_entry.get()
        if msg:
            try:
                encrypted = aes_encrypt(shared_key, msg.encode('utf-8'))
                message_length = len(encrypted)
                client.send(struct.pack('!I', message_length))
                client.sendall(encrypted)
                self.display_message(msg, is_sent=True)
                self.msg_entry.delete(0, END)
            except Exception as e:
                self.display_message(f"[ERROR] Could not send message: {e}", is_sent=True)
                print(f"[CLIENT ERROR] Sending message: {e}")

    def send_file(self):
        """
        Opens a file dialog, reads the selected file, encrypts it,
        and sends it to the server with a 'FILE' prefix.
        Only allowed if authenticated.
        """
        if not self.authenticated:
            self.login_status_label.configure(text="Please log in first.")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                filename = os.path.basename(file_path)
                with open(file_path, "rb") as f:
                    file_data = f.read()

                payload = b'FILE' + filename.encode('utf-8') + b'||' + file_data
                encrypted_payload = aes_encrypt(shared_key, payload)
                file_length = len(encrypted_payload)
                client.send(struct.pack('!I', file_length))
                client.sendall(encrypted_payload)
                self.display_message(f"Sent file: {filename}", is_sent=True)
            except FileNotFoundError:
                self.display_message(f"[ERROR] File not found: {filename}", is_sent=True)
                print(f"[CLIENT ERROR] File not found: {file_path}")
            except Exception as e:
                self.display_message(f"[ERROR] Could not send file: {e}", is_sent=True)
                print(f"[CLIENT ERROR] Sending file: {e}")


    def receive_messages(self):
        """
        Continuously receives and processes data from the server.
        Handles authentication responses and then regular messages/files.
        """
        while True:
            try:
                raw_length = client.recv(4)
                if not raw_length:
                    print("[CLIENT] Server disconnected.")
                    self.display_message("[SERVER DISCONNECTED]", is_sent=False)
                    break

                total_expected_bytes = struct.unpack('!I', raw_length)[0]
                received_bytes = 0
                chunks = []
                while received_bytes < total_expected_bytes:
                    bytes_to_read = total_expected_bytes - received_bytes
                    chunk = client.recv(min(bytes_to_read, 4096))
                    if not chunk:
                        print("[CLIENT ERROR] Connection closed unexpectedly while receiving data.")
                        self.display_message("[SERVER DISCONNECTED - Incomplete Data]", is_sent=False)
                        break
                    chunks.append(chunk)
                    received_bytes += len(chunk)

                if received_bytes < total_expected_bytes:
                    raise Exception("Incomplete data received from server.")

                full_data = b"".join(chunks)
                decrypted = aes_decrypt(shared_key, full_data)

                # --- Authentication Response Handling ---
                if not self.authenticated:
                    if decrypted.startswith(b'AUTH_SUCCESS'):
                        self.authenticated = True
                        self.login_status_label.configure(text="Login successful!", text_color="green")
                        self._toggle_chat_ui(True) # Show chat UI
                        print("[CLIENT] Authentication successful.")
                    elif decrypted.startswith(b'AUTH_FAILURE'):
                        self.login_status_label.configure(text="Login failed. Invalid credentials.", text_color="red")
                        self.login_button.configure(state="normal") # Re-enable login button
                        print("[CLIENT] Authentication failed.")
                    else:
                        # Unexpected message before authentication
                        self.login_status_label.configure(text="Unexpected message from server before authentication.", text_color="orange")
                        print(f"[CLIENT ERROR] Unexpected message before auth: {decrypted.decode('utf-8')}")
                else:
                    # Regular message/file handling after authentication
                    self.display_message(decrypted.decode('utf-8'), is_sent=False)

            except Exception as e:
                print(f"[CLIENT ERROR] Receiving messages: {e}")
                self.display_message(f"[ERROR] Receiving: {e}", is_sent=False)
                # If an error occurs after authentication, it might be a disconnection
                if self.authenticated:
                    self.authenticated = False
                    self.display_message("[SERVER DISCONNECTED]", is_sent=False)
                    self._toggle_chat_ui(False) # Go back to login screen
                break

    def on_typing(self, event):
        """
        Handles typing events to show/hide 'Typing...' status.
        """
        if not self.authenticated: return # Only show typing status if authenticated
        if not self.is_typing:
            self.typing_label.configure(text="Typing...")
            self.is_typing = True

        if self.typing_timer:
            self.after_cancel(self.typing_timer)

        self.typing_timer = self.after(2000, self.reset_typing_status)

    def reset_typing_status(self):
        """
        Resets the typing status after a delay.
        """
        self.typing_label.configure(text="")
        self.is_typing = False

    def toggle_emoji_picker(self):
        """
        Toggles the visibility of the emoji picker frame.
        Displays emoji buttons using text.
        """
        if not self.authenticated: return # Only allow if authenticated

        if self.emoji_frame and self.emoji_frame.winfo_exists():
            self.emoji_frame.destroy()
        else:
            self.emoji_frame = ctk.CTkFrame(self, width=300, height=100)
            self.emoji_frame.pack()

            emojis = ["😀", "😂", "😍", "😭", "🔥", "💯", "❤️", "🤔", "🤖"]
            for emoji in emojis:
                btn = ctk.CTkButton(self.emoji_frame, text=emoji, width=30,
                                    command=lambda e=emoji: self.insert_emoji(e),
                                    font=ctk.CTkFont(size=18))
                btn.pack(side="left", padx=5)

    def insert_emoji(self, emoji_char):
        """
        Inserts a selected emoji character into the message entry field.
        """
        if not self.authenticated: return # Only allow if authenticated

        current = self.msg_entry.get()
        self.msg_entry.delete(0, END)
        self.msg_entry.insert(0, current + emoji_char)

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
