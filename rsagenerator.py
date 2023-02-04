# import the necessary files
import os
import sys
import random
import cryptomath
import primegenerator


class RSAKeyGenerator:
    def __init__(self, key_file_name, key_size):
        self.txtName = key_file_name
        self.keySize = key_size

    def generateKey(self):

        # Generate Very large prime numbers from Rabin Miller Algorithm
        p = primegenerator.generateLargePrime(self.keySize)
        print("Берём любое простое число p... -> {}".format(p))

        # Generate very large prime numbers from Rabin Miller Algorithm
        q = primegenerator.generateLargePrime(self.keySize)
        print("Берём любое простое число q... -> {}".format(q))

        n = p * q  # Calculate n
        fi = (p - 1) * (q - 1)  # Calculate fi(n)
        print("Вычисляем n = p * q -> {}".format(n))
        print("Вычисляем fi = (p - 1) * (q - 1) -> {}".format(fi))

        while True:
            e = random.randrange(2 ** (self.keySize - 1), 2 ** self.keySize)
            # if the gcd of the selected 'e' and fi returns true, break
            if cryptomath.gcd(e, fi) == 1:
                break
        print("Находим e, что взаимнопростое с n и не больше чем функция Эйлера fi(n)... -> {}".format(e))

        d = cryptomath.findModInverse(e, fi)  # calculate d using mod inverse formula
        print("Ищем такое d, чтобы выполнялось условие (d * e) % fi = 1... -> {}".format(d))

        public_key = (n, e)
        private_key = (n, d)

        print("Мы нашли Public Key (n, e): ", public_key)
        print("Мы нашли Private Key (n, d): ", private_key)

        return public_key, private_key