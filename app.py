import socket
import threading
import sys
import time
import random
import struct

# Mengimpor fungsi-fungsi RSA dari rsa.py
from rsa import generate_keypair, encrypt, decrypt, get_local_ip
from storage import Storage

# ===============================
# Kelas Client
# ===============================

class ChatClient:
    def __init__(self):
        self.server_ip = ''
        self.server_port = 0
        self.server_public_key = None
        self.public_key = None
        self.private_key = None
        self.username = ''
        self.chatroom_password = ''
        self.client_socket = None
        self.stop_event = threading.Event()
        self.sequence_number = random.randint(0, 1000)  # Untuk TCP over UDP
        self.expected_ack = self.sequence_number + 1

    def start(self):
        self.display_welcome()
        self.get_server_info()
        self.setup_connection()
        self.authenticate()
        self.start_chat()

    def display_welcome(self):
        print("="*50)
        print("       Aplikasi Chat Enkripsi RSA UDP")
        print("="*50)

    def get_server_info(self):
        # Meminta pengguna untuk memilih penggunaan IP server
        while True:
            try:
                server_choice = input("Apakah Anda ingin menggunakan IP server Anda sendiri? (y/n): ").strip().lower()
                if server_choice in ['y', 'n']:
                    break
                else:
                    print("[!] Input tidak valid. Silakan masukkan 'y' atau 'n'.")
            except KeyboardInterrupt:
                print("\n[!] Program dihentikan oleh pengguna.")
                sys.exit()

        if server_choice == 'y':
            # Menggunakan IP lokal klien
            self.server_ip = get_local_ip()
            print(f"[+] Menggunakan IP lokal Anda sebagai server: {self.server_ip}")
        else:
            # Meminta input IP server
            while True:
                try:
                    self.server_ip = input("Masukkan IP server: ").strip()
                    if self.server_ip == '':
                        print("[!] IP server tidak boleh kosong. Silakan masukkan IP yang valid.")
                        continue
                    if self.validate_ip_format(self.server_ip):
                        break
                    else:
                        print("[!] Format IP tidak valid. Silakan masukkan IP yang valid.")
                except KeyboardInterrupt:
                    print("\n[!] Program dihentikan oleh pengguna.")
                    sys.exit()

        # Meminta port server
        while True:
            try:
                self.server_port = int(input("Masukkan port server (1024-65535): ").strip())
                if not 1024 <= self.server_port <= 65535:
                    print("[!] Port harus berada dalam rentang 1024-65535.")
                    continue
                break
            except ValueError:
                print("[!] Port harus berupa angka.")
            except KeyboardInterrupt:
                print("\n[!] Program dihentikan oleh pengguna.")
                sys.exit()

    def validate_ip_format(self, ip):
        """Validasi format IP tanpa menggunakan regex."""
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return False
        for item in parts:
            if not item.isdigit():
                return False
            num = int(item)
            if num < 0 or num > 255:
                return False
        return True

    def setup_connection(self):
        while True:
            try:
                # Membuat socket UDP dengan timeout
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.client_socket.settimeout(5)  # Timeout 5 detik

                # Meminta server public key
                print("[*] Meminta kunci publik server...")
                self.client_socket.sendto(b"REQUEST_PUBLIC_KEY", (self.server_ip, self.server_port))
                server_public_key_e, _ = self.client_socket.recvfrom(65536)
                server_public_key_n, _ = self.client_socket.recvfrom(65536)
                self.server_public_key = (int(server_public_key_e.decode('utf-8')), int(server_public_key_n.decode('utf-8')))
                print("[+] Kunci publik server diterima.")
                break  # Berhasil terhubung ke server
            except socket.timeout:
                print("[!] Tidak ada respons dari server. Pastikan IP dan port benar, serta server sedang berjalan.")
            except Exception as e:
                print(f"[!] Error saat menerima kunci publik server: \n{e}")
            finally:
                if self.server_public_key is None:
                    self.client_socket.close()
                    # Meminta kembali IP dan port server
                    print("[*] Silakan masukkan ulang IP atau server.")
                    self.get_server_info()
                else:
                    break

        # Menghasilkan kunci RSA klien
        print("[*] Menghasilkan kunci RSA klien...")
        self.public_key, self.private_key = generate_keypair()

        # TCP over UDP: Melakukan tiga-way handshake
        if not self.three_way_handshake():
            print("[!] Gagal melakukan tiga-way handshake.")
            self.client_socket.close()
            sys.exit()

        # Mengirim kunci publik klien ke server melalui TCP over UDP
        try:
            print("[*] Mengirim kunci publik klien ke server...")
            # Menggabungkan kunci publik menjadi satu paket
            public_key_data = f"{self.public_key[0]}::{self.public_key[1]}".encode('utf-8')
            self.send_tcp_packet(public_key_data)
        except Exception as e:
            print(f"[!] Error saat mengirim kunci publik ke server: {e}")
            self.client_socket.close()
            sys.exit()

    def three_way_handshake(self):
        """Melakukan tiga-way handshake untuk TCP over UDP."""
        try:
            syn_packet = b'SYN' + struct.pack('!I', self.sequence_number)
            self.client_socket.sendto(syn_packet, (self.server_ip, self.server_port))
            print("[*] Mengirim SYN ke server...")
            data, _ = self.client_socket.recvfrom(1024)
            if data.startswith(b'SYN-ACK'):
                recv_seq = struct.unpack('!I', data[7:])[0]
                self.expected_ack = recv_seq + 1
                print("[*] Menerima SYN-ACK dari server...")
                ack_packet = b'ACK' + struct.pack('!I', self.expected_ack)
                self.client_socket.sendto(ack_packet, (self.server_ip, self.server_port))
                print("[*] Mengirim ACK ke server, koneksi terbentuk.")
                self.sequence_number += 1
                return True
            return False
        except socket.timeout:
            print("[!] Waktu koneksi habis saat melakukan tiga-way handshake.")
            return False

    def validate_password(self, password):
        """Validasi password minimal 8 huruf, harus ada huruf kapital dan simbol."""
        if len(password) < 8:
            return False
        has_upper = any(c.isupper() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        return has_upper and has_symbol

    def authenticate(self):
        # Autentikasi dengan password chatroom
        while True:
            try:
                self.chatroom_password = input("Masukkan password chatroom: ").strip()
                if self.chatroom_password == "":
                    print("[!] Password tidak boleh kosong.")
                    continue
                if not self.validate_password(self.chatroom_password):
                    print("[!] Password harus minimal 8 huruf, mengandung huruf kapital dan simbol.")
                    continue
                break
            except KeyboardInterrupt:
                print("\n[!] Program dihentikan oleh pengguna.")
                self.client_socket.close()
                sys.exit()

        encrypted_message = encrypt(self.server_public_key, f"AUTH PASSWORD {self.chatroom_password}")
        self.send_tcp_packet(encrypted_message)

        # Meminta username
        while True:
            try:
                self.username = input("Masukkan username Anda: ").strip()
                if self.username == "":
                    print("[!] Username tidak boleh kosong.")
                    continue

                encrypted_message = encrypt(self.server_public_key, f"AUTH USERNAME {self.username}")
                self.send_tcp_packet(encrypted_message)

                response_data = self.receive_tcp_packet()
                if not response_data:
                    print("[!] Tidak ada respons dari server.")
                    self.client_socket.close()
                    sys.exit()

                message = decrypt(self.private_key, response_data)

                if message == "USERNAME_OK":
                    print("[+] Username diterima. Ketik '/exit' untuk keluar dari chat.")
                    break
                elif message == "USERNAME_TAKEN":
                    print("[!] Username sudah digunakan. Silakan pilih username lain.")
                elif message == "AUTH_FAILED":
                    print("[!] Password salah.")
                    self.client_socket.close()
                    sys.exit()
                else:
                    print(f"[!] Respon tidak dikenal dari server: {message}")
                    self.client_socket.close()
                    sys.exit()
            except socket.timeout:
                print("[!] Tidak ada respons dari server. Pastikan server berjalan dan port benar.")
                self.client_socket.close()
                sys.exit()
            except KeyboardInterrupt:
                print("\n[!] Program dihentikan oleh pengguna.")
                self.client_socket.close()
                sys.exit()
            except Exception as e:
                print(f"[!] Error saat menerima respons dari server: {e}")
                self.client_socket.close()
                sys.exit()
    

    def send_tcp_packet(self, data):
        """Mengirim paket dengan simulasi TCP over UDP."""
        packet = struct.pack('!I', self.sequence_number) + data
        checksum = self.calculate_checksum(packet)
        packet += struct.pack('!H', checksum)
        self.client_socket.sendto(packet, (self.server_ip, self.server_port))
        self.sequence_number += 1

    def receive_tcp_packet(self):
        """Menerima paket dengan simulasi TCP over UDP."""
        try:
            data, _ = self.client_socket.recvfrom(65536)
            seq_num = struct.unpack('!I', data[:4])[0]
            payload = data[4:-2]
            recv_checksum = struct.unpack('!H', data[-2:])[0]

            # Verifikasi checksum
            packet_without_checksum = data[:-2]
            calc_checksum = self.calculate_checksum(packet_without_checksum)
            if calc_checksum != recv_checksum:
                print("[!] Checksum tidak valid. Paket mungkin korup.")
                return None

            return payload
        except socket.timeout:
            return None

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

    def start_chat(self):
        # Memulai thread untuk menerima dan mengirim pesan
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()

        self.send_messages()
        recv_thread.join()
        self.client_socket.close()

    def receive_messages(self):
        """Menerima pesan dari server."""
        while not self.stop_event.is_set():
            try:
                data = self.receive_tcp_packet()
                if not data:
                    continue

                message = decrypt(self.private_key, data)

                tag, actual_message = message.split(' ', 1)

                if tag in ["CHAT", "NOTIFY"]:
                    print('\r' + ' ' * 80 + '\r', end='', flush=True)
                    print(f"{actual_message}")
                    print("You: ", end='', flush=True)
                else:
                    print(f"\n[!] Pesan server: {message}")
            except socket.timeout:
                # Tidak melakukan apa-apa dan melanjutkan loop
                continue
            except Exception as e:
                print(f"\n[!] Error menerima pesan: {e}")
                break

    def send_messages(self):
        """Mengirim pesan ke server."""
        while not self.stop_event.is_set():
            try:
                message = input("You: ").strip()
                if message == "":
                    print("[!] Pesan tidak boleh kosong.")
                    continue

                if message.lower() == '/exit':
                    print("[*] Keluar dari chat...")
                    self.stop_event.set()
                    break
                else:
                    full_message = f"CHAT {self.username}: {message}"
                    encrypted_message = encrypt(self.server_public_key, full_message)
                    self.send_tcp_packet(encrypted_message)
            except KeyboardInterrupt:
                print("\n[*] Keluar dari chat...")
                self.stop_event.set()
                break
            except Exception as e:
                print(f"[!] Error mengirim pesan: {e}")
                self.stop_event.set()
                break

# ===============================
# Bagian Utama Program
# ===============================

def main():
    client = ChatClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[!] Program dihentikan oleh pengguna.")
        sys.exit()

if __name__ == "__main__":
    main()
