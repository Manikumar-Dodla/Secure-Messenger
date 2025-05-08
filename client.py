import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

HOST = '127.0.0.1'
PORT = 8000

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Client")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(root)
        self.entry.pack(fill=tk.X, padx=10)
        self.entry.bind("<Return>", self.send_message)

        self.sock = None
        self.server_pub_key = None
        self.key_pair = RSA.generate(2048)
        self.cipher_rsa = PKCS1_OAEP.new(self.key_pair)

        self.start_client()

    def start_client(self):
        threading.Thread(target=self.client_thread, daemon=True).start()

    def client_thread(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
            self.append_text("[Client] Connected to server.\n")

            # Receive server's public key and send our public key
            server_pub_key_data = self.sock.recv(4096)
            self.server_pub_key = RSA.import_key(server_pub_key_data)
            self.server_cipher = PKCS1_OAEP.new(self.server_pub_key)
            self.sock.send(self.key_pair.publickey().export_key())

            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                decrypted = self.cipher_rsa.decrypt(base64.b64decode(data))
                self.append_text(f"[Server]: {decrypted.decode()}\n")
        except Exception as e:
            self.append_text(f"[Client] Error: {e}\n")

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg and self.sock and self.server_pub_key:
            encrypted = self.server_cipher.encrypt(msg.encode())
            self.sock.send(base64.b64encode(encrypted))
            self.append_text(f"[You]: {msg}\n")
            self.entry.delete(0, tk.END)

    def append_text(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg)
        self.text_area.see(tk.END)
        self.text_area.config(state='disabled')

root = tk.Tk()
app = ClientGUI(root)
root.mainloop()
