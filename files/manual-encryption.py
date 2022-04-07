#!/usr/bin/env python
# -*- coding: utf-8 -*-
from Crypto.Random import get_random_bytes

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4
#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

message = b'Hello'
iv = b'bit'

print(iv)

# rc4 seed est composé de IV+clé
seed = iv+key

# calcul icv
icv = binascii.crc32(message)

# creation du cipher
cipher = RC4(seed, streaming=False)

# Encrypt
ciphertext = cipher.crypt(message + icv.to_bytes(4, byteorder='little'))


arp = rdpcap('arp.cap')[0]  

icv_encrypted=ciphertext[-4:]
ciphertext_encrypted = ciphertext[:-4]

arp.iv = iv
arp.wepdata = ciphertext_encrypted
arp.icv = int.from_bytes(icv_encrypted, "little")


wrpcap('filtered.pcap', arp, append=True)





