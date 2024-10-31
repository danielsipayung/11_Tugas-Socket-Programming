# storage.py

import csv
import os

class Storage:
    FILENAME = "chat_log.csv"

    @staticmethod
    def save_message(room, username, encrypted_message):
        # Check if the file already exists, if not create it and write headers
        file_exists = os.path.isfile(Storage.FILENAME)
        with open(Storage.FILENAME, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Room", "Username", "Message"])  # Write header if file is new
            writer.writerow([room, username, encrypted_message])

    @staticmethod
    def load_messages(room):
        if not os.path.exists(Storage.FILENAME):
            return []

        with open(Storage.FILENAME, mode='r', newline='') as file:
            reader = csv.reader(file)
            return [row for row in reader if row[0] == room]
