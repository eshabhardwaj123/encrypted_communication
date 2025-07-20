import customtkinter as ctk
import threading
import socket
import os
import struct # Added for packing/unpacking message lengths
from tkinter import END, filedialog
from crypto_utils import generate_keys, derive_shared_key, aes_encrypt, aes_decrypt, deserialize_public_key
from cryptography.hazmat.primitives import serialization

# Initial theme setting (can be changed by button)
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
    exit() # Exit if connection fails

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
    exit() # Exit if key exchange fails


class ChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Client - Secure Chat")
        self.geometry("600x650") # Increased height to accommodate theme button
        self.resizable(False, False)

        self.current_theme = "dark" # Track current theme

        # Theme changing button
        self.theme_button = ctk.CTkButton(self, text="Toggle Theme", command=self.toggle_theme)
        self.theme_button.pack(pady=5) # Placed at the top

        # Frame for displaying chat messages
        self.chat_frame = ctk.CTkScrollableFrame(self, width=560, height=440)
        self.chat_frame.pack(pady=10, padx=20)

        # Label for typing status
        self.typing_label = ctk.CTkLabel(self, text="", text_color="grey")
        self.typing_label.pack()

        # Frame for message input and buttons
        self.entry_frame = ctk.CTkFrame(self)
        self.entry_frame.pack(pady=10, padx=20, fill="x")

        # Message entry field
        self.msg_entry = ctk.CTkEntry(self.entry_frame, width=350, placeholder_text="Type a message...")
        self.msg_entry.pack(side="left", padx=(10, 5), pady=10)
        self.msg_entry.bind("<KeyRelease>", self.on_typing)

        # Emoji button
        # Emojis are inherently colorful, CTkLabel/Button will render them as such
        self.emoji_button = ctk.CTkButton(self.entry_frame, text="😀", width=30, command=self.toggle_emoji_picker,
                                          font=ctk.CTkFont(size=18)) # Increased font size for better emoji display
        self.emoji_button.pack(side="left", padx=5)

        # File send button
        self.file_button = ctk.CTkButton(self.entry_frame, text="�", width=30, command=self.send_file,
                                         font=ctk.CTkFont(size=18)) # Increased font size for better emoji display
        self.file_button.pack(side="left", padx=5)

        # Send message button
        self.send_button = ctk.CTkButton(self.entry_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left", padx=5)

        self.emoji_frame = None
        self.is_typing = False
        self.typing_timer = None

        # Start thread for receiving messages from the server
        threading.Thread(target=self.receive_messages, daemon=True).start()

        # Apply initial theme colors
        self._apply_theme_colors()

    def _apply_theme_colors(self):
        """Applies colors based on the current theme."""
        if self.current_theme == "dark":
            # Dark theme: dark blue background, green font for messages
            self.configure(fg_color="#2b2b2b") # Main window background
            self.chat_frame.configure(fg_color="#2b2b2b") # Scrollable frame background
            self.entry_frame.configure(fg_color="#2b2b2b") # Entry frame background
            self.typing_label.configure(text_color="grey") # Typing label color
            # Message bubble colors will be handled by display_message
        else: # Light theme
            # Light theme: white background, black font
            self.configure(fg_color="white") # Main window background
            self.chat_frame.configure(fg_color="white") # Scrollable frame background
            self.entry_frame.configure(fg_color="white") # Entry frame background
            self.typing_label.configure(text_color="grey") # Typing label color (can be adjusted)

        # Redraw existing messages with new colors
        for widget in self.chat_frame.winfo_children():
            if isinstance(widget, ctk.CTkLabel):
                message = widget.cget("text")
                # Determine if it was a sent message based on its current anchor
                is_sent = widget.cget("anchor") == "e"
                widget.destroy() # Remove old label
                self.display_message(message, is_sent=is_sent) # Redraw with new colors


    def toggle_theme(self):
        """Toggles between dark and light themes."""
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.current_theme = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.current_theme = "dark"
        self._apply_theme_colors() # Apply the new theme colors

    def display_message(self, message, is_sent=False):
        """
        Displays a message in the chat frame with theme-specific colors.
        Args:
            message (str): The message text to display.
            is_sent (bool): True if the message was sent by this client, False otherwise.
        """
        align = "e" if is_sent else "w"
        if self.current_theme == "dark":
            bubble_color = "#1f538d" if is_sent else "#3a3a3a" # Dark blue for sent, dark grey for received
            text_color = "lightgreen" if is_sent else "white" # Green for sent, white for received
        else: # Light theme
            bubble_color = "#ADD8E6" if is_sent else "#E0E0E0" # Light blue for sent, light grey for received
            text_color = "black" # Black for both sent and received

        label = ctk.CTkLabel(self.chat_frame, text=message, text_color=text_color,
                             fg_color=bubble_color, corner_radius=10,
                             anchor="w", justify="left", wraplength=480)
        label.pack(anchor=align, padx=10, pady=5)
        self.chat_frame._parent_canvas.yview_moveto(1.0)


    def send_message(self):
        """
        Sends a text message typed in the entry field to the server.
        """
        msg = self.msg_entry.get()
        if msg:
            try:
                # Encrypt the message (encoded to bytes)
                encrypted = aes_encrypt(shared_key, msg.encode('utf-8'))
                message_length = len(encrypted)
                # Prepend the message length as a 4-byte unsigned integer
                client.send(struct.pack('!I', message_length))
                # Send the encrypted message data
                client.sendall(encrypted) # Use sendall to ensure all bytes are sent
                self.display_message(msg, is_sent=True)
                self.msg_entry.delete(0, END)
            except Exception as e:
                self.display_message(f"[ERROR] Could not send message: {e}", is_sent=True)
                print(f"[CLIENT ERROR] Sending message: {e}")

    def send_file(self):
        """
        Opens a file dialog, reads the selected file, encrypts it,
        and sends it to the server with a 'FILE' prefix.
        """
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                filename = os.path.basename(file_path)
                with open(file_path, "rb") as f:
                    file_data = f.read()

                # Combine filename and file data with a separator
                # Prefix with b'FILE' to signal file transfer to the server
                payload = b'FILE' + filename.encode('utf-8') + b'||' + file_data

                # Encrypt the entire payload
                encrypted_payload = aes_encrypt(shared_key, payload)
                file_length = len(encrypted_payload)
                # Prepend the file data length as a 4-byte unsigned integer
                client.send(struct.pack('!I', file_length))
                # Send the encrypted file data
                client.sendall(encrypted_payload) # Use sendall to ensure all bytes are sent
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
        It first reads a 4-byte length prefix, then reads the exact number of bytes.
        Handles both regular text messages and server-sent messages.
        """
        while True:
            try:
                # First, receive the 4-byte length prefix
                raw_length = client.recv(4)
                if not raw_length: # Server disconnected or sent empty data
                    print("[CLIENT] Server disconnected.")
                    self.display_message("[SERVER DISCONNECTED]", is_sent=False)
                    break # Exit loop if server disconnects

                # Unpack the length from bytes to an integer
                total_expected_bytes = struct.unpack('!I', raw_length)[0]

                received_bytes = 0
                chunks = []
                while received_bytes < total_expected_bytes:
                    # Calculate how many bytes are still needed
                    bytes_to_read = total_expected_bytes - received_bytes
                    # Receive up to the remaining bytes, or the buffer size (4096)
                    chunk = client.recv(min(bytes_to_read, 4096))
                    if not chunk: # Connection closed unexpectedly mid-message
                        print("[CLIENT ERROR] Connection closed unexpectedly while receiving data.")
                        self.display_message("[SERVER DISCONNECTED - Incomplete Data]", is_sent=False)
                        break
                    chunks.append(chunk)
                    received_bytes += len(chunk)

                if received_bytes < total_expected_bytes:
                    # This means the connection broke before all data was received
                    raise Exception("Incomplete data received from server.")

                full_data = b"".join(chunks)

                # Decrypt the received full data
                decrypted = aes_decrypt(shared_key, full_data)
                # Decode the decrypted bytes to a string for display
                self.display_message(decrypted.decode('utf-8'), is_sent=False)

            except Exception as e:
                print(f"[CLIENT ERROR] Receiving messages: {e}")
                self.display_message(f"[ERROR] Receiving: {e}", is_sent=False)
                break # Exit loop on error or disconnection

    def on_typing(self, event):
        """
        Handles typing events to show/hide 'Typing...' status.
        """
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
        """
        if self.emoji_frame and self.emoji_frame.winfo_exists():
            self.emoji_frame.destroy()
        else:
            self.emoji_frame = ctk.CTkFrame(self, width=300, height=100)
            self.emoji_frame.pack()

            emojis = ["😀", "😂", "😍", "😭", "🔥", "💯", "❤️", "🤔", "🤖"]
            for emoji in emojis:
                # Emojis are inherently colorful, just ensure a good font size
                btn = ctk.CTkButton(self.emoji_frame, text=emoji, width=30,
                                    command=lambda e=emoji: self.insert_emoji(e),
                                    font=ctk.CTkFont(size=18)) # Increased font size
                btn.pack(side="left", padx=5)

    def insert_emoji(self, emoji):
        """
        Inserts a selected emoji into the message entry field.
        """
        current = self.msg_entry.get()
        self.msg_entry.delete(0, END)
        self.msg_entry.insert(0, current + emoji)

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
