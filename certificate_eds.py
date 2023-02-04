import zlib


class Eds:
    def __init__(self, hello_message, client, server):
        self.client = client
        self.server = server
        self.chunk_len = 5
        self.signature(hello_message)

    def chunks(self, hash):
        for start in range(0, len(hash), self.chunk_len):
            yield hash[start:start + self.chunk_len][::-1]

    def block_hash_creating(self, n, d, hello_message):
        # чтобы уменьшить вычисления, мы будем подписывать десятеричный код хеша приветственного сообщения по-блочно
        int16_hash = str(zlib.crc32(hello_message.encode('utf-8')))
        int10_hash = str(int(int16_hash, 16))

        block_hash = []
        sign_block_hash = []

        for chunk in self.chunks(int10_hash[::-1]):
            block_hash.append(int(chunk))
            sign_block_hash.append(pow(int(chunk), d, n))

        print("Сервер хеширует приветственное сообщение пользователя, делит его на чанки по 5 символов с конца в 10СС,"
              "\nгде нули опускаются для удобного вычисления, затем подписывает их:"
              "\nmessage -> {}"
              "\nhash -> {} 16СС -> {} 10CC"
              "\nchunked_hash -> {}\nsigned_hash -> {}\nПо формуле [sign] = [hash]**d%n".format(hello_message, int16_hash, int10_hash, block_hash[::-1], sign_block_hash[::-1]))
        return list(reversed(sign_block_hash))

    def block_hash_decoding(self, n, e, signed_hash):
        block_hash = []
        block_hash_str = ""

        for chunk in signed_hash:
            block_hash.append(pow(int(chunk), e, n))

        for i in block_hash:
            block_hash_str += "".join(str(i).zfill(5))

        print("Пользователь открывает подпись сервера и получает хеш-сумму по формуле:\n[decode] = [sign]**e%n,\nпосле чего сверяет с хешом своего приветственного сообщения сообщение:\nsigned_hash -> {}\ndecoded_sign -> {} 10СС\nP.S. Также алгоритм достраивает недостающие нули у всех чанков кроме первого, например, 465 -> 00465".format(signed_hash, block_hash))
        return block_hash_str.strip("0")

    def signature(self, hello_message):
        machine_private_key_d = self.server.private_key[1]
        machine_public_key_e = self.server.public_key[1]
        machine_public_key_n = self.server.public_key[0]  # or machine_private_key_n = self.server.private_key[0]

        print("Пусть сервер должен доказать свою подленность, \n"
              "значит сервер должен подписать что-то своим приватным ключом (n: {}, d: {}), \n"
              "чтобы любой желающий мог его публичным ключом (n: {}, e: {}) удостоверится в его действительности, \n"
              "поэтому отправим на сервер приветственное сообщение: {}"
              .format(machine_public_key_n, machine_private_key_d, machine_public_key_n, machine_public_key_e, hello_message))
        print("                =============================                     ")

        sign_process = self.block_hash_creating(machine_public_key_n, machine_private_key_d, hello_message)
        print("Далее сервер отправит пользователю сообщение с подписью")
        print("                =============================                     ")

        decode_process = self.block_hash_decoding(machine_public_key_n, machine_public_key_e, sign_process)
        print("decoded_hash -> {} 10CC -> {} 16CC".format(decode_process, hex(int(decode_process))[2:]))
        print("                =============================                     ")

        print("Теперь сравним в шеснадцетеричной системе хеш, полученый из подписи, с хешом сообщения, которое отсылали изначально серверу")

        print("{} and {}? Если хеши сошлись, то значит мы установили контакт с нужной машиной".format(str(zlib.crc32(hello_message.encode('utf-8'))), hex(int(decode_process))[2:]))
        print("                =============================                     ")
        return str(zlib.crc32(hello_message.encode('utf-8')) == decode_process)
