#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.all import *
from scapy.layers.dot11 import RadioTap

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
message = b'\xaa' * 9 # Taille de 9 minimum sinon le ICV ne se vérifie pas
iv = b'bit'

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

# On change les valeurs du paquet 
ciphertext = ciphertext[:-4]
arp.iv = iv
arp.wepdata = ciphertext
arp.icv = icv_encrypted

print ('Text: ' + ciphertext.hex())
print ("IV :  " + iv.hex())

# Pour reset le fichier pcap
arp[RadioTap].len = None

# On écrit dans un nouveau fichier.
wrpcap('filtered.pcap', arp)





