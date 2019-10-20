#!/usr/bin/python

import base64
from Crypto import Random
from Crypto.Cipher import AES
import string
import random
from .functions import *


# block_size
block_size = AES.block_size

# function to pad the input text
pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)


def encrypt_command(key, plain):
    iv = Random.new().read(AES.block_size)
    decoded_key = base64.b64decode(key)
    aesobj = AES.new(decoded_key, AES.MODE_CBC, iv)
    data = pad(plain)
    encd = aesobj.encrypt(data)
    return base64.b64encode(iv + encd)

def decrypt_command(key, encrypted_text):
    decoded_key = base64.b64decode(key)
    data = base64.b64decode(encrypted_text)
    iv = data[:block_size]
    aesobj = AES.new(decoded_key, AES.MODE_CBC, iv)
    decd = aesobj.decrypt(data)[block_size:].decode("UTF-8")
    return decd
