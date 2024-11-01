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
        self.addr_chatroom_map = {}      # {addr: chatroom_password}
        self.chatrooms = {}              # {chatroom_password: set(username)}
        self.sequence_numbers = {}       # For TCP over UDP
        self.expected_acks = {}

        self.server_ip = '0.0.0.0'
        self.server_port = self.get_server_port()

        # Membuat socket UDP
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((self.server_ip, self.server_port))

        print("Menghasilkan kunci RSA server...")
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
                    # Tambahkan logging atau penanganan tambahan jika diperlukan
        except KeyboardInterrupt:
            print("\nServer dimatikan.")
        finally:
            self.server_socket.close()

    def handle_packet(self, data, addr):
        try:
            # Memeriksa apakah data adalah permintaan kunci publik
            if data == b"REQUEST_PUBLIC_KEY":
                # Mengirim kunci publik server ke klien
                self.server_socket.sendto(str(self.public_key[0]).encode('utf-8'), addr)
                self.server_socket.sendto(str(self.public_key[1]).encode('utf-8'), addr)
                return

            # TCP over UDP: Memproses tiga-way handshake
            if data.startswith(b'SYN'):
                recv_seq = struct.unpack('!I', data[3:])[0]
                server_seq = random.randint(0, 1000)
                syn_ack_packet = b'SYN-ACK' + struct.pack('!I', server_seq)
                self.server_socket.sendto(syn_ack_packet, addr)
                print(f"[DEBUG] Mengirim SYN-ACK ke {addr}")
                self.sequence_numbers[addr] = server_seq + 1
                self.expected_acks[addr] = recv_seq + 1
                return
            elif data.startswith(b'ACK'):
                recv_ack = struct.unpack('!I', data[3:])[0]
                print(f"[DEBUG] Koneksi dengan {addr} terbentuk.")
                return

            # Menerima paket data
            seq_num = struct.unpack('!I', data[:4])[0]
            payload = data[4:-2]
            recv_checksum = struct.unpack('!H', data[-2:])[0]

            # Verifikasi checksum
            packet_without_checksum = data[:-2]
            calc_checksum = self.calculate_checksum(packet_without_checksum)
            if calc_checksum != recv_checksum:
                print(f"[!] Checksum tidak valid dari {addr}. Paket mungkin korup.")
                return

            # Simpan sequence number
            self.sequence_numbers[addr] = seq_num
            self.expected_acks[addr] = seq_num + 1

            # Jika belum menerima kunci publik klien, terima sekarang
            if addr not in self.client_keys:
                # Menerima kunci publik klien dalam satu paket
                public_key_data = payload.decode('utf-8')
                e_str, n_str = public_key_data.split('::')
                client_public_key_e = int(e_str)
                client_public_key_n = int(n_str)
                self.client_keys[addr] = (client_public_key_e, client_public_key_n)
                print(f"[DEBUG] Menerima kunci publik dari {addr}: {self.client_keys[addr]}")
                return

            # Proses data
            message = decrypt(self.private_key, payload)
            print(f"[DEBUG] Pesan didekripsi dari {addr}: {message}")
            self.process_message(addr, message)
        except Exception as e:
            print(f"Error menangani paket dari {addr}: {e}")
            # Tambahkan penanganan tambahan jika diperlukan

    def calculate_checksum(self, data):
        """Menghitung checksum sederhana."""
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
                        self.send_response(addr, "USERNAME_OK")
                        print(f"User {value} telah bergabung ke chatroom.")

                        # Notifikasi ke klien lain di chatroom yang sama
                        self.notify_clients(addr, f"NOTIFY {value} telah bergabung ke chatroom.")

                        # Mengirim pesan yang telah disimpan kepada klien yang baru bergabung
                        saved_messages = Storage.load_messages(chatroom_password)
                        for sender_username, saved_message in saved_messages:
                            # Encrypt the message with the client's public key
                            encrypted_message = encrypt(self.client_keys[addr], f"CHAT {sender_username}: {saved_message}")
                            self.send_tcp_packet(addr, encrypted_message)
                else:
                    self.send_response(addr, "AUTH_FAILED")
            elif tag == "CHAT":
                chatroom_password = self.addr_chatroom_map.get(addr)
                if chatroom_password:
                    # Meneruskan pesan ke klien lain di chatroom yang sama
                    self.notify_clients(addr, message)

                    # Menyimpan pesan ke storage
                    sender_username = actual_message.split(":")[0].strip()
                    message_content = ":".join(actual_message.split(":")[1:]).strip()
                    Storage.save_message(chatroom_password, sender_username, message_content)
            elif tag == "FILE":
                # Menangani file biner
                chatroom_password = self.addr_chatroom_map.get(addr)
                if chatroom_password:
                    # Meneruskan file ke klien lain di chatroom yang sama
                    self.notify_clients(addr, message)

                    # Menyimpan pesan ke storage
                    sender_username = actual_message.split(":")[0].strip()
                    file_info = ":".join(actual_message.split(":")[1:]).strip()
                    Storage.save_message(chatroom_password, sender_username, f"[File] {file_info}")
            else:
                print(f"[DEBUG] Tag tidak dikenal dari {addr}: {tag}")
        except Exception as e:
            print(f"Error memproses pesan dari {addr}: {e}")
            # Tambahkan penanganan tambahan jika diperlukan

    def send_response(self, addr, response):
        """Mengenkripsi dan mengirim respons ke klien."""
        encrypted_response = encrypt(self.client_keys[addr], response)
        self.send_tcp_packet(addr, encrypted_response)

    def send_tcp_packet(self, addr, data):
        """Mengirim paket dengan simulasi TCP over UDP."""
        seq_num = self.sequence_numbers.get(addr, random.randint(0, 1000))
        packet = struct.pack('!I', seq_num) + data
        checksum = self.calculate_checksum(packet)
        packet += struct.pack('!H', checksum)
        self.server_socket.sendto(packet, addr)
        self.sequence_numbers[addr] = seq_num + 1

    def notify_clients(self, sender_addr, message):
        """Mengirim notifikasi ke klien lain di chatroom yang sama."""
        chatroom_password = self.addr_chatroom_map.get(sender_addr)
        for client_addr, _ in self.clients:
            if client_addr != sender_addr and self.addr_chatroom_map.get(client_addr) == chatroom_password:
                encrypted_message = encrypt(self.client_keys[client_addr], message)
                self.send_tcp_packet(client_addr, encrypted_message)

if __name__ == "__main__":
    server = ChatServer()
    server.start()
