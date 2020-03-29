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


def encrypt_command(keyb64, ivb64, plain):
    decoded_key = base64.b64decode(keyb64)
    decoded_iv = base64.b64decode(ivb64)
    aesobj = AES.new(decoded_key, AES.MODE_CBC, decoded_iv)
    data = pad(plain)
    try:
        encd = aesobj.encrypt(data)
        return base64.b64encode(encd)
    except:
        return ""


def decrypt_command(keyb64, ivb64, cipher):
    decoded_key = base64.b64decode(keyb64)
    decoded_iv = base64.b64decode(ivb64)
    data = base64.b64decode(cipher)
    aesobj = AES.new(decoded_key, AES.MODE_CBC, decoded_iv)
    decd = aesobj.decrypt(data)[0:].decode("UTF-8")
    return decd.strip('\x00')