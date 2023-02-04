from rsagenerator import RSAKeyGenerator


class Machine:
    def __init__(self, key_file_name):
        self.key_file_name = key_file_name
        self.public_key = ()
        self.private_key = ()
        self.my_partial_key = None
        self.co_partial_key = None
        self.master_key = None
        self.connection()

    def connection(self):
        print('{}`s Создаёт ключи RSA...'.format(self.key_file_name))
        gen = RSAKeyGenerator(self.key_file_name, 16)
        self.public_key, self.private_key = gen.generateKey()  # Key size is 1024-bits and txtName starts with key_file
        print("{}`s Готов...".format(self.key_file_name))
        print("                =============================                     ")

    def generate_partial_key(self, sub_key):
        print("Для клиента нужны:\nclient[private_key: {}; public_key: {};]\nserver[public_key: {};]".format(self.private_key[1], self.public_key[1], sub_key[1]))
        print("По формуле: partial_key = client_public_key(e)**client_private_key(d)%server_public_key(e)")
        self.my_partial_key = pow(self.public_key[1], self.private_key[1], sub_key[1])

    def generate_master_key(self, sub_key):
        self.master_key = pow(self.co_partial_key, self.private_key[1], sub_key[1])
        return self.master_key

    def encrypt_message(self, message):
        encrypted_message = ""
        key = self.master_key
        for c in message:
            encrypted_message += chr(ord(c) + key)
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        decrypted_message = ""
        key = self.master_key
        for c in encrypted_message:
            decrypted_message += chr(ord(c) - key)
        return decrypted_message


class Host(Machine):
    def __init__(self, key_file_name):
        super().__init__(key_file_name)

    def generate_partial_key(self, sub_key):
        print("Для сервера нужны:\nserver[private_key: {}; public_key: {};]\nclient[public_key: {};]".format(self.private_key[1], self.public_key[1], sub_key[1]))
        print("По формуле: partial_key = client_public_key(e)**server_private_key(d)%server_public_key(e)")
        self.my_partial_key = pow(sub_key[1], self.private_key[1], self.public_key[1])

    def generate_master_key(self, sub_key=None):
        self.master_key = pow(self.co_partial_key, self.private_key[1], self.public_key[1])
        return self.master_key
