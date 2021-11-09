# Credit to Creel for his amazing AES tutorial, and to https://github.com/kpielacki/whats-a-creel-aes for demonstrating the decryption method
# A lot of this code is very verbose and C like because I plan to bring it into rust

# from encrypt import AES_Encrypt
# from decrypt import AES_Decrypt
from encrypt import *
from decrypt import *

if __name__ == "__main__":
    message = bytearray(b"This is a message we will encrypt with AES!")
    key = bytearray(list(range(1, 17)))
    enc = AES_Encrypt(message, key)
    print(enc.hex())
    dec = AES_Decrypt(enc, key)
    print(dec.decode())