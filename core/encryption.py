#!/usr/bin/python

import base64
from Crypto import Random
from Crypto.Cipher import AES
import string
import random
from functions import *


# set the IV
iv = Random.new().read(AES.block_size)

# block_size
block_size = 16

# function to pad the input text
pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)


def encrypt_command(key, plain):
    decoded_key = base64.b64decode(key)
    aesobj = AES.new(decoded_key, AES.MODE_CBC, iv)
    data = iv + pad(plain)
    encd = aesobj.encrypt(data)
    return base64.b64encode(encd)

def decrypt_command(key, encrypted_text):
    decoded_key = base64.b64decode(key)
    aesobj = AES.new(decoded_key, AES.MODE_CBC, iv)
    data = base64.b64decode(encrypted_text)
    decd = aesobj.decrypt(data)[16:]
    return decd
