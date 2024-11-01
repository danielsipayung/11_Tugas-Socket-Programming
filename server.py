import socket
import sys
import threading
import struct
import random

# Mengimpor fungsi-fungsi RSA dari rsa.py
from rsa import generate_keypair, encrypt, decrypt
from storage import Storage

# ===============================
# Kelas Server
# ===============================

class ChatServer:
    def __init__(self):
        self.client_keys = {}            # {addr: public_key}
        self.clients = []                # List of tuples (addr, username)
        self.addr_username_map = {}      # {addr: username}
        self.addr_chatroom_map = {}      # {addr: chatroom_password}
        self.chatrooms = {}              # {chatroom_password: set(username)}
        self.sequence_numbers = {}       # For TCP over UDP
        self.expected_acks = {}

        self.server_ip = '0.0.0.0'
        self.server_port = self.get_server_port()

        # Membuat socket UDP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.server_ip, self.server_port))

        self.public_key, self.private_key = generate_keypair()

        print(f"Server berjalan di {self.server_ip}:{self.server_port}")
        print("Menunggu klien untuk terhubung...")

    def get_server_port(self):
        while True:
            try:
                port = int(input("Masukkan port server (1024-65535): ").strip())
                if 1024 <= port <= 65535:
                    return port
                else:
                    print("Port harus berada dalam rentang 1024-65535.")
            except ValueError:
                print("Input tidak valid. Silakan masukkan angka.")

    def start(self):
        try:
            while True:
                try:
                    data, addr = self.server_socket.recvfrom(65536)
                    threading.Thread(target=self.handle_packet, args=(data, addr)).start()
                except Exception as e:
                    print(f"Error dalam loop utama: {e}")
        except KeyboardInterrupt:
            print("\nServer dimatikan.")
        finally:
            self.server_socket.close()

    def handle_packet(self, data, addr):
        try:
            if data == b"REQUEST_PUBLIC_KEY":
                self.server_socket.sendto(str(self.public_key[0]).encode('utf-8'), addr)
                self.server_socket.sendto(str(self.public_key[1]).encode('utf-8'), addr)
                print(f"[INFO] Mengirim kunci publik ke {addr}")
                return

            if data.startswith(b'SYN'):
                recv_seq = struct.unpack('!I', data[3:])[0]
                server_seq = random.randint(0, 1000)
                syn_ack_packet = b'SYN-ACK' + struct.pack('!I', server_seq)
                self.server_socket.sendto(syn_ack_packet, addr)
                self.sequence_numbers[addr] = server_seq + 1
                self.expected_acks[addr] = recv_seq + 1
                print(f"[INFO] Tiga-way handshake dimulai dengan {addr}")
                return
            elif data.startswith(b'ACK'):
                recv_ack = struct.unpack('!I', data[3:])[0]
                print(f"[INFO] Tiga-way handshake selesai dengan {addr}")
                return

            seq_num = struct.unpack('!I', data[:4])[0]
            payload = data[4:-2]
            recv_checksum = struct.unpack('!H', data[-2:])[0]

            packet_without_checksum = data[:-2]
            calc_checksum = self.calculate_checksum(packet_without_checksum)
            if calc_checksum != recv_checksum:
                print(f"[!] Checksum tidak valid dari {addr}. Paket mungkin korup.")
                return

            self.sequence_numbers[addr] = seq_num
            self.expected_acks[addr] = seq_num + 1

            if addr not in self.client_keys:
                public_key_data = payload.decode('utf-8')
                e_str, n_str = public_key_data.split('::')
                client_public_key_e = int(e_str)
                client_public_key_n = int(n_str)
                self.client_keys[addr] = (client_public_key_e, client_public_key_n)
                print(f"[INFO] Menerima kunci publik dari {addr}")
                return

            message = decrypt(self.private_key, payload)
            print(f"[RECV] Dari {addr}: {message}")
            self.process_message(addr, message)
        except Exception as e:
            print(f"Error menangani paket dari {addr}: {e}")

    def calculate_checksum(self, data):
        checksum = 0
        for i in range(0, len(data), 2):
            if i+1 < len(data):
                word = (data[i] << 8) + data[i+1]
            else:
                word = (data[i] << 8)
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = ~checksum & 0xFFFF
        return checksum

    def process_message(self, addr, message):
        try:
            tag, actual_message = message.split(' ', 1)

            if tag == "AUTH":
                key, value = actual_message.split(' ', 1)
                if key == "PASSWORD":
                    chatroom_password = value
                    if chatroom_password not in self.chatrooms:
                        self.chatrooms[chatroom_password] = set()
                    self.addr_chatroom_map[addr] = chatroom_password
                elif key == "USERNAME":
                    chatroom_password = self.addr_chatroom_map.get(addr)
                    if chatroom_password is None:
                        self.send_response(addr, "AUTH_FAILED")
                        return
                    if value in self.chatrooms[chatroom_password]:
                        self.send_response(addr, "USERNAME_TAKEN")
                    else:
                        self.chatrooms[chatroom_password].add(value)
                        self.clients.append((addr, value))
                        self.addr_username_map[addr] = value
                        self.send_response(addr, "USERNAME_OK")
                        print(f"[JOIN] User '{value}' telah bergabung ke chatroom.")
                        self.notify_clients(addr, f"NOTIFY {value} telah bergabung ke chatroom.")

                        saved_messages = Storage.load_messages(chatroom_password)
                        for sender_username, saved_message in saved_messages:
                            encrypted_message = encrypt(self.client_keys[addr], f"CHAT {sender_username}: {saved_message}")
                            self.send_tcp_packet(addr, encrypted_message)
                else:
                    self.send_response(addr, "AUTH_FAILED")
            elif tag == "CHAT":
                chatroom_password = self.addr_chatroom_map.get(addr)
                if chatroom_password:
                    self.notify_clients(addr, message)
                    sender_username = actual_message.split(":")[0].strip()
                    message_content = ":".join(actual_message.split(":")[1:]).strip()
                    Storage.save_message(chatroom_password, sender_username, message_content)
                    print(f"[CHAT] {sender_username}: {message_content}")
            elif tag == "EXIT":
                username = actual_message.strip()
                self.handle_exit(addr, username)
            else:
                print(f"[WARN] Tag tidak dikenal dari {addr}: {tag}")
        except Exception as e:
            print(f"Error memproses pesan dari {addr}: {e}")

    def handle_exit(self, addr, username):
        chatroom_password = self.addr_chatroom_map.get(addr)
        if chatroom_password:
            # Hapus username dari chatroom
            self.chatrooms[chatroom_password].discard(username)
            # Hapus addr dari peta addr_chatroom_map
            del self.addr_chatroom_map[addr]
        # Hapus dari daftar klien
        self.clients = [client for client in self.clients if client[0] != addr]
        # Hapus mapping addr ke username
        if addr in self.addr_username_map:
            del self.addr_username_map[addr]
        # Hapus kunci publik klien
        if addr in self.client_keys:
            del self.client_keys[addr]
        # Hapus sequence number
        if addr in self.sequence_numbers:
            del self.sequence_numbers[addr]
        if addr in self.expected_acks:
            del self.expected_acks[addr]
        print(f"[EXIT] User '{username}' telah keluar dari chatroom.")
        # Notifikasi ke klien lain
        self.notify_clients(addr, f"NOTIFY {username} telah keluar dari chatroom.")

    def send_response(self, addr, response):
        encrypted_response = encrypt(self.client_keys[addr], response)
        self.send_tcp_packet(addr, encrypted_response)

    def send_tcp_packet(self, addr, data):
        seq_num = self.sequence_numbers.get(addr, random.randint(0, 1000))
        packet = struct.pack('!I', seq_num) + data
        checksum = self.calculate_checksum(packet)
        packet += struct.pack('!H', checksum)
        self.server_socket.sendto(packet, addr)
        self.sequence_numbers[addr] = seq_num + 1

    def notify_clients(self, sender_addr, message):
        chatroom_password = self.addr_chatroom_map.get(sender_addr)
        if chatroom_password:
            for client_addr, _ in self.clients:
                if client_addr != sender_addr and self.addr_chatroom_map.get(client_addr) == chatroom_password:
                    encrypted_message = encrypt(self.client_keys[client_addr], message)
                    self.send_tcp_packet(client_addr, encrypted_message)

if __name__ == "__main__":
    server = ChatServer()
    server.start()
