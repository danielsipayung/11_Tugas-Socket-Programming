import socket
import threading
import time
from storage import Storage

class ChatServer:
    def __init__(self, ip='0.0.0.0', port=5000):
        self.server_ip = ip
        self.server_port = port
        self.rooms = {}  # Dictionary to hold room members
        self.clients = {}  # Dictionary to map address to (username, room)
        self.heartbeat_times = {}  # To track last heartbeat time for each client
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.server_ip, self.server_port))
        self.client_sequence = {}  # Track sequence numbers for each client
        self.room_state_changed = True  # A flag to track room state changes
        print(f"UDP Server started at {self.server_ip}:{self.server_port}")

        # Start a thread to monitor changes and display active rooms and clients
        threading.Thread(target=self.display_active_rooms, daemon=True).start()
        # Start a thread to check for disconnected clients
        threading.Thread(target=self.check_heartbeats, daemon=True).start()

    def display_active_rooms(self):
        while True:
            if self.room_state_changed:  # Display only if there are changes
                print("\n----- Active Rooms and Clients -----")
                if not self.rooms:
                    print("No active rooms.")
                else:
                    for room, members in self.rooms.items():
                        member_usernames = [self.clients[addr][0] for addr in members]
                        print(f"Room '{room}': {len(members)} active member(s) -> {member_usernames}")
                print("-----------------------------------\n")
                self.room_state_changed = False  # Reset the flag after displaying

    def check_heartbeats(self):
        while True:
            current_time = time.time()
            disconnected_clients = []

            # Identify clients that haven't sent a heartbeat recently
            for addr, last_heartbeat in self.heartbeat_times.items():
                if current_time - last_heartbeat > 15:  # 15 seconds without a heartbeat
                    disconnected_clients.append(addr)

            # Remove each identified disconnected client
            for addr in disconnected_clients:
                self.remove_client(addr)

            time.sleep(5)  # Check heartbeats every 5 seconds

    def send_saved_messages(self, addr, room):
        # Load previous messages from the storage
        saved_messages = Storage.load_messages(room)
        for message_data in saved_messages:
            _, username, encrypted_message = message_data
            # Send each saved message to the client who just joined
            self.sock.sendto(f"{username}:{encrypted_message}".encode('utf-8'), addr)
            print(f"[Server] Sending saved message to {addr} in room '{room}': {message_data}")

    def handle_client(self, data, addr):
        try:
            message = data.decode('utf-8')
            print(f"[Server] Received message from {addr}: {message}")

            # Handle three-way handshake
            if message == "SYN":
                print(f"Received SYN from {addr}, sending SYN-ACK...")
                self.sock.sendto("SYN-ACK".encode('utf-8'), addr)
                return
            elif message == "ACK":
                print(f"Received ACK from {addr}, connection established.")
                self.client_sequence[addr] = 0  # Initialize sequence tracking for this client
                return

            # Handle username validation request
            if message.startswith("USERNAME:"):
                requested_username = message.split(":")[1].strip().lower()
                existing_usernames = [name[0].lower() for name in self.clients.values()]
                if requested_username in existing_usernames:
                    self.sock.sendto("INVALID".encode('utf-8'), addr)
                else:
                    self.sock.sendto("VALID".encode('utf-8'), addr)
                return

            # Check for heartbeat message
            if message.startswith("HEARTBEAT:"):
                username = message.split(":")[1]
                self.heartbeat_times[addr] = time.time()  # Update last heartbeat time
                return

            # Check if it's a registration message
            if ";" in message:
                parts = message.split(";")
                if len(parts) != 2 or not parts[0] or not parts[1]:
                    return
                
                username, room = parts

                if room not in self.rooms:
                    self.rooms[room] = []  # Create the room if it doesn't exist

                # Add client to room if not already present
                if addr not in self.rooms[room]:
                    self.rooms[room].append(addr)
                    self.room_state_changed = True  # Mark change
                    print(f"Client '{username}' joined room '{room}'.")
                    self.heartbeat_times[addr] = time.time()  # Record initial heartbeat

                # Update client mapping
                self.clients[addr] = (username, room)

                # Send saved messages to the client after they join the room
                self.send_saved_messages(addr, room)
                return

            # Handle encrypted message forwarding with sequence acknowledgment
            if message.count(":") >= 3:
                parts = message.split(":", 3)
                seq_num = int(parts[0])  # Get sequence number from message
                username, room, encrypted_message = parts[1], parts[2], parts[3]

                # Verify that the room exists before forwarding the message
                if room not in self.rooms:
                    return

                # Check if sequence number is in order
                if addr in self.client_sequence and seq_num > self.client_sequence[addr]:
                    # Update sequence number for client
                    self.client_sequence[addr] = seq_num
                    self.sock.sendto(f"ACK:{seq_num}".encode('utf-8'), addr)  # Send acknowledgment

                    # Save the message to storage and forward to other clients in the same room
                    Storage.save_message(room, username, encrypted_message)
                    for client in self.rooms[room]:
                        if client != addr:
                            self.sock.sendto(f"{username}:{encrypted_message}".encode('utf-8'), client)
                            print(f"[Server] Forwarded message from {username} to {client} in room '{room}'.")

        except Exception as e:
            print(f"Error handling client: {e}")

    def remove_client(self, addr):
        if addr in self.clients:
            username, room = self.clients[addr]
            self.rooms[room].remove(addr)
            print(f"Client '{username}' disconnected from room '{room}'.")
            self.room_state_changed = True  # Mark change to update display

            # Clean up if the room is empty
            if not self.rooms[room]:
                del self.rooms[room]

            del self.clients[addr]
            del self.heartbeat_times[addr]

    def start(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                threading.Thread(target=self.handle_client, args=(data, addr)).start()
            except Exception as e:
                print(f"Server error while receiving data: {e}")

if __name__ == "__main__":
    server = ChatServer()
    server.start()
