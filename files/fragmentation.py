#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""
import math
import struct

from scapy.all import *
import binascii
from rc4 import RC4
from scapy.all import *
from scapy.layers.dot11 import RadioTap
from textwrap3 import wrap

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
message = "Salut je suis le message chiffre1  Salut je suis le message chiffre2 Salut je suis le message chiffre3" # Taille de 9 minimum sinon le ICV ne se vérifie pas

iv = b'bit'
print("IV :  " + iv.hex())

arp = rdpcap('arp.cap')[0]
arp.iv = iv #modifie l'iv de la trame ici, car il n'y a besoin de le faire qu'une seule fois pour tous les paquets

#rc4 seed est composée de IV+clé
seed = iv+key

# creation du cipher
cipher = RC4(seed, streaming=False)

#Sépare le message en trois, une partie pour la data de chaque fragment
fragments = wrap(message, math.ceil(len(message)/3))

#pour chaque fragment on va créer un fichier pcap
for i in range(3):
    #converti le message en bytes
    msg = str.encode(fragments[i])
    # La taille du message minimum doit être de 9 bytes sinon l'ICV ne se vérifie pas
    # On ajoute donc neuf fois le caractère au début du message si il fait moins que 9 caractères
    if len(msg) < 9:
        msg = (b'\x00' * 9) +  msg

    #calcul icv
    icv = binascii.crc32(msg)
    #encrypt
    ciphertext = cipher.crypt(msg + struct.pack('I', icv))
    icv_encrypted = struct.unpack('!L', ciphertext[-4:])[0]#icv représente les 4 dernier bytes

    #Change les valeurs du packet
    ciphertext = ciphertext[:-4]
    arp.wepdata = ciphertext
    arp.icv = icv_encrypted

    print('ICV:' + str(icv_encrypted))
    print('Text: ' + ciphertext.hex())

    #si c'est un des deux premiers fragments il faut mettre le champ more fragment à 1
    if i < 2:
        arp.FCfield.MF = 1
    else :
        arp.FCfield.MF = False

    #set le numero du fragment
    arp.SC = i

    # Pour reset le fichier pcap
    arp[RadioTap].len = None

    # On écrit dans un nouveau fichier.
    wrpcap('fragments.pcap', arp, append=True)