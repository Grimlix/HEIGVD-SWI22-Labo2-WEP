#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
from scapy.all import *
from scapy.layers.dot11 import RadioTap

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
message = b'\x00' * 10
iv = b'\x00' * 3

# ON récupère le fichier pcap d'avant pour le copier et juste changer ses valeurs
arp = rdpcap('arp.cap')[0]  

# rc4 seed est composé de IV+clé
seed = iv+key
# creation du cipher
cipher = RC4(seed, streaming=False)
# calcul icv
icv = binascii.crc32(message)
# Encrypt
ciphertext = cipher.crypt(message + struct.pack('I', icv))

icv_encrypted = struct.unpack('!L', ciphertext[-4:])[0]
ciphertext = ciphertext[:-4]

arp.iv = iv
arp.wepdata = ciphertext
arp.icv = icv_encrypted

arp[RadioTap].len = None

wrpcap('filtered.pcap', arp)





