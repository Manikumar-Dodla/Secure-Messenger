import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

HOST = '127.0.0.1'
PORT = 8000

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Server")

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry = tk.Entry(root)
        self.entry.pack(fill=tk.X, padx=10)
        self.entry.bind("<Return>", self.send_message)

        self.client_socket = None
        self.client_pub_key = None
        self.key_pair = RSA.generate(2048)
        self.cipher_rsa = PKCS1_OAEP.new(self.key_pair)

        self.start_server()

    def start_server(self):
        threading.Thread(target=self.server_thread, daemon=True).start()

    def server_thread(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(1)
        self.append_text("[Server] Listening for connections...\n")
        self.client_socket, addr = server.accept()
        self.append_text(f"[Server] Client connected from {addr}\n")

        # Exchange public keys
        self.client_socket.send(self.key_pair.publickey().export_key())
        client_pub_key_data = self.client_socket.recv(4096)
        self.client_pub_key = RSA.import_key(client_pub_key_data)
        self.client_cipher = PKCS1_OAEP.new(self.client_pub_key)

        while True:
            try:
                data = self.client_socket.recv(4096)
                if not data:
                    break
                decrypted = self.cipher_rsa.decrypt(base64.b64decode(data))
                self.append_text(f"[Client]: {decrypted.decode()}\n")
            except Exception as e:
                self.append_text(f"[Server] Error: {e}\n")
                break

    def send_message(self, event=None):
        msg = self.entry.get()
        if msg and self.client_socket and self.client_pub_key:
            encrypted = self.client_cipher.encrypt(msg.encode())
            self.client_socket.send(base64.b64encode(encrypted))
            self.append_text(f"[You]: {msg}\n")
            self.entry.delete(0, tk.END)

    def append_text(self, msg):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, msg)
        self.text_area.see(tk.END)
        self.text_area.config(state='disabled')

root = tk.Tk()
app = ServerGUI(root)
root.mainloop()
