# cryptography.py

class Cryptography:
    @staticmethod
    def encrypt(message, shift=10):
        encrypted = ""
        for char in message:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                encrypted += chr((ord(char) + shift - shift_base) % 26 + shift_base)
            else:
                encrypted += char
        return encrypted

    @staticmethod
    def decrypt(encrypted_message, shift=10):
        decrypted = ""
        for char in encrypted_message:
            if char.isalpha():
                shift_base = 65 if char.isupper() else 97
                decrypted += chr((ord(char) - shift - shift_base) % 26 + shift_base)
            else:
                decrypted += char
        return decrypted
