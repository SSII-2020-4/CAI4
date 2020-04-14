import json
import os
import OpenSSL
import jks
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
        # Ruta de los ficheros a cifrar o descifrar
        self.files_path = "files"
        self.init_menu()

    def init_menu(self):
        titulo = "Menú principal"
        subtitulo = "Programa para cifrar ficheros con AES 256 GCM"
        prologue = "Para poder encriptar ficheros tiene que estar situados en la carpeta files."\
            " Los ficheros *.encrypted y *.decrypted se situarán en la misma carpeta."

        if not os.path.exists("./my_keystore.jks"):
            prologue += " PARA HACER USO DE LAS FUNCIONES DE ENCRIPTADO Y DESENCRIPTADO, DEBE CREAR UN ALMACÉN DE CLAVES Y UNA CLAVE (3)."

        menu = ConsoleMenu(titulo, subtitulo, prologue_text=prologue)

        cifrado = FunctionItem("Cifrado del fichero", self.encrypt)
        descifrado = FunctionItem("Descifrado del fichero", self.decrypt)
        generado_claves = FunctionItem("Generar nueva clave privada", self.generate_key)

        menu.append_item(cifrado)
        menu.append_item(descifrado)
        menu.append_item(generado_claves)

        menu.show()

    def validacionExisteKeyStore(funcion):
        if not os.path.exists("./my_keystore.jks"):
            print("No existe un almacén de claves. Realize el apartado 3 para crear uno.")
            input("Introduzca cualquier caracter para volver al menú")
        else:
            funcion()

    
    def encrypt(self):
        if not os.path.exists("./my_keystore.jks"):
            print("No existe un almacén de claves. Realize el apartado 3 para crear uno.")
            input("Introduzca cualquier caracter para volver al menú: ")
        else:
            # Comprobación de que el archivo existe
            invalid_file = True
            while invalid_file:
                try:
                    file_to_encrypt = input("Inserte nombre del fichero: ")
                    input_file = open(os.path.abspath(os.path.join("..", self.files_path, file_to_encrypt)), 'rb')
                    invalid_file = False
                except FileNotFoundError as e:
                    print("El archivo '" + file_to_encrypt + "' no existe en la carpeta files")
            
            # Comprueba que la contraseña del almacén es válida
            incorrect_password = True
            while(incorrect_password):
                password_keystore = input("Introduza la contraseña del almacén de claves: ")
                try:
                    stored_keys = jks.KeyStore.load("./my_keystore.jks", password_keystore).entries
                    stored_keys_as_list = list(stored_keys.values())
                    incorrect_password = False
                except jks.util.KeystoreSignatureException as e:
                    print("Contraseña incorrecta, inténtelo otra vez.")

            # Comprueba que la selección de la clave es correcta 
            incorrect_key = True
            while(incorrect_key):
                alias_key_selected = input("Introduza el alias de la clave (Alias almacenados: " + str([stored_key.alias for stored_key in stored_keys_as_list])+ "): ")
                if alias_key_selected in [stored_key.alias for stored_key in stored_keys_as_list]:
                    incorrect_key = False
                else:
                    print("No existe una clave con el alias '" + alias_key_selected + "'")

            private_key = stored_keys[alias_key_selected].pkey

            output_file = open(os.path.abspath(os.path.join("..", self.files_path, file_to_encrypt + '.encrypted')), 'w')
            # Crear el objeto de cifrado y cifrar los datos
            cipher = AES.new(private_key, mode=AES.MODE_GCM)

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
        if not os.path.exists("./my_keystore.jks"):
            print("No existe un almacén de claves. Realize el apartado 3 para crear uno.")
            input("Introduzca cualquier caracter para volver al menú: ")
        else:
            # Comprobación que el fichero existe
            invalid_file = True
            while invalid_file:
                try:
                    file_to_decrypt = input("Inserte nombre del fichero (Introduzca el nombre entero junto a la extension del archivo): ")
                    input_file = open(os.path.abspath(os.path.join("..", self.files_path, file_to_decrypt)), 'r')
                    invalid_file = False
                except FileNotFoundError as e:
                    print("El archivo '" + file_to_decrypt + "' no existe en la carpeta files")
            
            # Comprobación de que la contraseña del almacén de claves es correcta
            incorrect_password = True
            while(incorrect_password):
                password_keystore = input("Introduza la contraseña del almacén de claves: ")
                try:
                    stored_keys = jks.KeyStore.load("./my_keystore.jks", password_keystore).entries
                    stored_keys_as_list = list(stored_keys.values())
                    incorrect_password = False
                except jks.util.KeystoreSignatureException as e:
                    print("Contraseña incorrecta, inténtelo otra vez.")

            # Comprobación de que la clave seleccionada es válida
            incorrect_key = True
            while(incorrect_key):
                alias_key_selected = input("Introduza el alias de la clave (Alias almacenados: " + str([stored_key.alias for stored_key in stored_keys_as_list])+ "): ")
                if alias_key_selected in [stored_key.alias for stored_key in stored_keys_as_list]:
                    incorrect_key = False
                else:
                    print("No existe una clave con el alias '" + alias_key_selected + "'")
            
            private_key = stored_keys[alias_key_selected].pkey
            b64 = json.load(input_file)
            output_file = open(os.path.abspath(os.path.join("..", self.files_path,file_to_decrypt.replace(".encrypted", "") + '.decrypted')), 'w')

            json_k = ['nonce', 'ciphertext', 'tag']
            jv = {k: b64decode(b64[k]) for k in json_k}

            # Crear el objeto de cifrado y cifrar los datos
            cipher = AES.new(private_key, AES.MODE_GCM, nonce=jv["nonce"])

            try:
                # Mantener leyendo el archivo en el buffer, cifrando y escribiendo en el nuevo fichero
                plain_text = cipher.decrypt_and_verify(
                    jv["ciphertext"],
                    jv["tag"]
                )
                output_file.write(plain_text.decode('ascii'))
            except ValueError as e:
                print("El archivo no se ha podido descifrar ¿Ha elegido la clave con la que cifró el archivo?")
                input("Introduca cualquier caracter para volver al menú.")
            finally:
                # Cerrar la entrada y salida de los ficheros
                output_file.close()
                input_file.close()
    
    def generate_key(self):
        #Si no existe el keystore, hay que generarlo
        if not os.path.exists("./my_keystore.jks"):
            password_new_keystore = input("Introduza una contraseña para generar el almacén de claves: ")
            keystore = jks.KeyStore.new('jks', [])
            keystore.save('./my_keystore.jks', password_new_keystore)

        # Para acceder al ks, hay que poner la contraseña correcta. Si es incorrecta, se solicita otra vez.
        incorrect_password = True
        while(incorrect_password):
            password_keystore = input("Introduza la contraseña del almacén de claves: ")
            try:
                stored_keys = list(jks.KeyStore.load("./my_keystore.jks", password_keystore).entries.values())
                incorrect_password = False
            except jks.util.KeystoreSignatureException as e:
                print("Contraseña incorrecta, inténtelo otra vez.")
        
        # Se pide el alias de la clave para que pueda ser identificada posteriormente. Si hay existe una clave con ese alias, se solicita otra vez
        invalid_name = True
        while (invalid_name):
            alias_private_key = input("Introduzca un alias para indentificar a la nueva clave privada: ")
            if not alias_private_key in [private_key_stored.alias for private_key_stored in stored_keys]:
                invalid_name = False
            else:
                print("Ya existe una clave privada con el alias: '" + alias_private_key + "'")
        

        passphrase = input("Introduca una contraseña para generar la clave: ")
        kdf_salt = get_random_bytes(32)
        dumped_key = PBKDF2(passphrase, kdf_salt, dkLen=32)
        
        stored_keys.append(jks.PrivateKeyEntry.new(alias_private_key, [], dumped_key, 'rsa_raw'))
        keystore = jks.KeyStore.new('jks', stored_keys)
        keystore.save('./my_keystore.jks', password_keystore)
        print("Clave generada con éxito")
        

if __name__ == '__main__':
    c = Ciphers()
