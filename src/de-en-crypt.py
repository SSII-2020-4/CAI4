import json
import os
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


class Ciphers:
    def __init__(self):
        # Generate the key
        self.key = self.key_generation()
        # self.buffer_size = 65536  # 64kb
        # Path of files to encrypt/decrypt
        self.files_path = "files"

    def key_generation(self):
        # Key generation if not exists
        # 32 bytes * 8 = 256 bits (1 byte = 8 bits)
        key_location = "key.bin"
        if os.path.exists(key_location):
            file_in = open(key_location, "rb")  # Read bytes
            key = file_in.read()  # This key should be the same
            file_in.close()
        else:
            kdf_salt = get_random_bytes(32)
            default_passphrase = "I!LIKE!IKE!"
            user_passphrase = input("SECRET PASSPHRASE INPUT\n"
                                    "You will need this to decrypt\n"
                                    "Default: " +
                                    str(default_passphrase) + "\n"
                                    "Enter secret passphrase:"
                                    )
            passphrase = user_passphrase or default_passphrase
            print("Passphrase used: " + str(passphrase))
            key = PBKDF2(passphrase, kdf_salt, dkLen=32)
            # Save the key to a file
            file_out = open(key_location, "wb")
            file_out.write(key)
            file_out.close()
        print("AES Encryption Key: " + str(key))
        return key

    def encrypt(self, file_to_encrypt):
        # Open the input and output files
        input_file = open(os.path.join(self.files_path, file_to_encrypt), 'rb')
        output_file = open(
            os.path.join(
                self.files_path,
                file_to_encrypt + '.encrypted'
            ), 'w')

        # Create the cipher object and encrypt the data
        cipher = AES.new(self.key, mode=AES.MODE_GCM)

        # Keep reading the file into the buffer, encrypting then writing to the new file
        ciphertext, tag = cipher.encrypt_and_digest(input_file.read())

        json_k = ['nonce', 'ciphertext', 'tag']
        json_v = [
            b64encode(cipher.nonce).decode('utf-8'),
            b64encode(ciphertext).decode('utf-8'),
            b64encode(tag).decode('utf-8')
        ]

        output_file.write(json.dumps(dict(zip(json_k, json_v))))

        # Close the input and output files
        input_file.close()
        output_file.close()

    def decrypt(self, file_to_encrypt):
        # Open the input and output files
        with open(
                os.path.join(
                    self.files_path,
                    file_to_encrypt + '.encrypted'
                ), 'r') as json_file:
            b64 = json.load(json_file)
        output_file = open(
            os.path.join(
                self.files_path,
                file_to_encrypt + '.decrypted'
            ), 'w')

        json_k = ['nonce', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}

        # Create the cipher object and encrypt the data
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=jv["nonce"])

        # Keep reading the file into the buffer, decrypting then writing to the new file
        plain_text = cipher.decrypt_and_verify(
            jv["ciphertext"],
            jv["tag"]
        )
        output_file.write(plain_text.decode('ascii'))

        # Close the input and output files
        # input_file.close()
        output_file.close()


if __name__ == '__main__':
    c = Ciphers()
    # c.encrypt("text")
    c.decrypt("text")
