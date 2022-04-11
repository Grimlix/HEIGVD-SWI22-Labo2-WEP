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
message = b'hello'

#La taille du message minimum doit être de 9 bytes sinon l'ICV ne se vérifie pas
#On ajoute donc neuf fois le caractère au début du message si il fait moins que 9 caractères
if len(message) < 9:
    message = (b'\x00' * 9) + message
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
icv_encrypted = struct.unpack('!L', ciphertext[-4:])[0] #icv représente les 4 dernier bytes

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
wrpcap('trame_chiffree.pcap', arp)





