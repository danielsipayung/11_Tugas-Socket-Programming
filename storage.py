# storage.py

class Storage:
    FILENAME = "chat_log.txt"

    @staticmethod
    def save_message(chatroom, username, message):
        with open(Storage.FILENAME, 'a') as f:
            f.write(f"{chatroom}::{username}::{message}\n")

    @staticmethod
    def load_messages(chatroom):
        messages = []
        try:
            with open(Storage.FILENAME, 'r') as f:
                for line in f:
                    parts = line.strip().split("::")
                    if len(parts) == 3 and parts[0] == chatroom:
                        messages.append((parts[1], parts[2]))
        except FileNotFoundError:
            pass
        return messages
