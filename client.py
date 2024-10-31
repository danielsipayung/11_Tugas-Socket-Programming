import socket
import threading
import time
import sys  # Import sys for exiting the app
from cryptography import Cryptography

class ChatClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3)  # Set a timeout of 3 seconds for receiving messages
        self.keep_running = True
        self.binary_mode = False  # Flag to toggle binary message mode
        self.sequence_number = 0  # Sequence number for outgoing messages
        self.ack_number = 0       # Acknowledgment number for incoming messages
        self.connected = False

    def connect_to_server(self, server_ip, server_port):
        try:
            # Start three-way handshake
            self.sock.sendto("SYN".encode('utf-8'), (server_ip, server_port))
            print("Sent SYN, waiting for SYN-ACK...")

            # Wait for server response
            response, _ = self.sock.recvfrom(1024)
            if response.decode('utf-8') == "SYN-ACK":
                print("Received SYN-ACK, sending ACK...")
                self.sock.sendto("ACK".encode('utf-8'), (server_ip, server_port))
                self.connected = True
                print(f"Connected to server at {server_ip}:{server_port}")
                return True
            else:
                print("Three-way handshake failed.")
                return False
        except socket.timeout:
            print(f"The server at {server_ip}:{server_port} does not exist or is unreachable.")
            return False
        except socket.error as e:
            if e.errno == 10054:  # Handle the specific error
                print("server not exist")
            else:
                print(f"Failed to connect to server: {e}")
            return False

    def check_username(self, username, server_ip, server_port):
        self.sock.sendto(f"USERNAME:{username}".encode('utf-8'), (server_ip, server_port))
        try:
            response, _ = self.sock.recvfrom(1024)
            return response.decode('utf-8').strip() == "VALID"
        except socket.timeout:
            print("No response from server for username validation.")
            return False

    def send_message(self, server_ip, server_port, room, username, message):
        if not self.connected:
            print("Not connected to the server.")
            return
        try:
            self.sequence_number += 1  # Increment sequence number for each message
            if self.binary_mode:
                message_bytes = message.encode('utf-8')
                message_to_send = f"{self.sequence_number}:{username}:{room}:".encode('utf-8') + message_bytes
            else:
                encrypted_message = Cryptography.encrypt(message)
                message_to_send = f"{self.sequence_number}:{username}:{room}:{encrypted_message}".encode('utf-8')

            self.sock.sendto(message_to_send, (server_ip, server_port))
        except Exception as e:
            print(f"Failed to send message: {e}")

    def send_heartbeat(self, server_ip, server_port, username):
        while self.keep_running:
            try:
                heartbeat_message = f"HEARTBEAT:{username}"
                self.sock.sendto(heartbeat_message.encode('utf-8'), (server_ip, server_port))
                time.sleep(5)
            except Exception as e:
                print(f"Failed to send heartbeat: {e}")

    def receive_messages(self):
        while self.keep_running:
            try:
                message, _ = self.sock.recvfrom(1024)
                if message:
                    try:
                        decoded_message = message.decode('utf-8')
                        if decoded_message.startswith("ACK:"):
                            # Acknowledge message receipt
                            self.ack_number = int(decoded_message.split(":")[1])
                        else:
                            sender, encrypted_message = decoded_message.split(":", 1)
                            decrypted_message = Cryptography.decrypt(encrypted_message.strip())
                            print(f"[{sender}]\n {decrypted_message}\n")  # Single newline
                    except UnicodeDecodeError:
                        print("Received binary data:", message)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def display_options(self):
        print("\n--- Feature Options ---")
        print("1. Type 'quit()' to exit the chat application.")
        print("2. Type 'binary()' to toggle binary message mode on/off.")
        print("----------------------\n")

    def start(self, server_ip, server_port):
        if self.connect_to_server(server_ip, server_port):
            while True:
                username = input("Enter your username: ")
                if self.check_username(username, server_ip, server_port):
                    print(f"Username '{username}' is available.")
                    break
                else:
                    print(f"Username '{username}' is already taken. Please choose a different username.")

            room = input("Enter room to join or create: ")

            registration_message = f"{username};{room}"
            self.sock.sendto(registration_message.encode('utf-8'), (server_ip, server_port))

            threading.Thread(target=self.send_heartbeat, args=(server_ip, server_port, username), daemon=True).start()
            threading.Thread(target=self.receive_messages, daemon=True).start()
            print(f"\n\nYou can start typing messages. Type 'opt()' to view feature options.\n")

            while True:
                message = input()
                if message == "quit()":
                    self.keep_running = False
                    print("Exiting the chat application...")
                    sys.exit()  # Fully exit the app
                elif message == "opt()":
                    self.display_options()
                elif message == "binary()":
                    self.binary_mode = not self.binary_mode
                    mode = "on" if self.binary_mode else "off"
                    print(f"Binary message mode is now {mode}.")
                else:
                    self.send_message(server_ip, server_port, room, username, message)

if __name__ == "__main__":
    client = ChatClient()
    while True:
        server_ip = input(f"\n\nEnter server IP: ")
        server_port = int(input("Enter server port: "))
        if client.start(server_ip, server_port):
            break
        else:
            print("Please try entering the server IP and port again.")
