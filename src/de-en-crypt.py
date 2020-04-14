import json
import os
from base64 import b64decode, b64encode
from mimetypes import init

from consolemenu import ConsoleMenu
from consolemenu.items import FunctionItem
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


class Ciphers:
    def __init__(self):
        # Generar la clave
        self.key = self.key_generation()
        # Ruta de los ficheros a cifrar o descifrar
        self.files_path = "files"
        self.init_menu()

    def init_menu(self):
        titulo = "Menú principal"
        subtitulo = "Programa para cifrar ficheros con AES 256 GCM"
        prologue = "Para poder encriptar ficheros tiene que estar situados en la carpeta files."\
            " Los ficheros *.encrypted y *.decrypted se situarán en la misma carpeta."

        menu = ConsoleMenu(titulo, subtitulo, prologue_text=prologue)

        cifrado = FunctionItem("Cifrado del fichero", self.encrypt)
        descifrado = FunctionItem("Descifrado del fichero", self.decrypt)

        menu.append_item(cifrado)
        menu.append_item(descifrado)

        menu.show()

    def key_generation(self):
        # Generacion de la clave si no existe
        # 32 bytes * 8 = 256 bits (1 byte = 8 bits)
        key_location = "key.bin"
        if os.path.exists(key_location):
            file_in = open(key_location, "rb")  # Lee los bytes
            key = file_in.read()  # Esta clave debe ser la misma
            file_in.close()
        else:
            kdf_salt = get_random_bytes(32)
            default_passphrase = "grupo4"
            user_passphrase = input("Inserte una frase para generar la clave \n"
                                    "Por defecto: " +
                                    str(default_passphrase) + "\n"
                                    "Inserte la frase:"
                                    )
            passphrase = user_passphrase or default_passphrase
            key = PBKDF2(passphrase, kdf_salt, dkLen=32)
            # Guarda la clave en un fichero
            file_out = open(key_location, "wb")
            file_out.write(key)
            file_out.close()
        return key

    def encrypt(self):
        # Abrir los archivos de salida o entrada
        file_to_encrypt = input("Inserte nombre del fichero: ")
        input_file = open(os.path.join(self.files_path, file_to_encrypt), 'rb')
        output_file = open(
            os.path.join(
                self.files_path,
                file_to_encrypt + '.encrypted'
            ), 'w')

        # Crear el objeto de cifrado y cifrar los datos
        cipher = AES.new(self.key, mode=AES.MODE_GCM)

        # Mantener leyendo el archivo en el buffer, cifrando y escribiendo en el nuevo fichero
        ciphertext, tag = cipher.encrypt_and_digest(input_file.read())

        json_k = ['nonce', 'ciphertext', 'tag']
        json_v = [
            b64encode(cipher.nonce).decode('utf-8'),
            b64encode(ciphertext).decode('utf-8'),
            b64encode(tag).decode('utf-8')
        ]

        output_file.write(json.dumps(dict(zip(json_k, json_v))))

        # Cerrar la entrada y salida de los ficheros
        input_file.close()
        output_file.close()

    def decrypt(self):
        # Abrir la entrada y salida de los ficheros
        file_to_encrypt = input("Inserte nombre del fichero: ")
        with open(
                os.path.join(
                    self.files_path,
                    file_to_encrypt
                ), 'r') as json_file:
            b64 = json.load(json_file)
        output_file = open(
            os.path.join(
                self.files_path,
                file_to_encrypt.replace(".encrypted", "") + '.decrypted'
            ), 'w')

        json_k = ['nonce', 'ciphertext', 'tag']
        jv = {k: b64decode(b64[k]) for k in json_k}

        # Crear el objeto de cifrado y cifrar los datos
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=jv["nonce"])

        # Mantener leyendo el archivo en el buffer, cifrando y escribiendo en el nuevo fichero
        plain_text = cipher.decrypt_and_verify(
            jv["ciphertext"],
            jv["tag"]
        )
        output_file.write(plain_text.decode('ascii'))

        # Cerrar la entrada y salida de los ficheros
        output_file.close()


if __name__ == '__main__':
    c = Ciphers()
