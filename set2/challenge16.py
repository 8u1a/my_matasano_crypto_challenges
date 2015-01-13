__author__ = 'christianbuia'

import random
from Crypto.Cipher import AES


def add_pkcs7_padding(message_bytes, blocksize):

    pad_length = blocksize - (len(message_bytes) % blocksize)

    for i in range(0, pad_length):
        message_bytes += bytes([pad_length])

    return message_bytes
#-----------------------------------------------------------------------------------------------------------------------


def strip_pkcs7_padding(plaintext):

    last_byte = plaintext[-1]

    for i in range(last_byte):
        if plaintext[-(i+1)] != last_byte:
            raise Exception("Error with PKCS7 Padding.")

    plaintext = plaintext[:-last_byte]
    return plaintext
#-----------------------------------------------------------------------------------------------------------------------


def generateRandom16bytes():
    ints = []
    for i in range(16):
        ints.append(random.randint(0,255))
    return bytes(ints)
#-----------------------------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------------------------


#always 16 bytes
def decrypt_aes128(message, key, pad=False):
    decobj = AES.new(key, AES.MODE_ECB)
    return decobj.decrypt(message)
#-----------------------------------------------------------------------------------------------------------------------


#always 16 bytes
def encrypt_aes128(message, key, pad=False):
    decobj = AES.new(key, AES.MODE_ECB)
    return decobj.encrypt(message)
#-----------------------------------------------------------------------------------------------------------------------


def encrypt_aes128_cbc(message, key, iv):

    message = add_pkcs7_padding(message, 16)

    blocks = [message[x:x+16] for x in range(0, len(message), 16)]
    encrypted_blocks = []

    for block in blocks:
        encrypted_block = bytearray()
        for b_count in range(len(block)):
            encrypted_block.append(block[b_count] ^ iv[b_count])

        iv = encrypt_aes128(bytes(encrypted_block), key)
        encrypted_blocks.append(iv)

    ciphertext = b''
    for block in encrypted_blocks:
        ciphertext += block

    return ciphertext
#-----------------------------------------------------------------------------------------------------------------------


def decrypt_aes128_cbc(message, key, iv):

    blocks = [message[x:x+16] for x in range(0, len(message), 16)]
    decrypted_blocks = []

    for block in blocks:
        dec_block = bytearray(decrypt_aes128(bytes(block), key))
        decrypted_block = bytearray()
        for b_count in range(len(dec_block)):
            decrypted_block.append(dec_block[b_count] ^ iv[b_count])

        iv = block
        decrypted_blocks.append(decrypted_block)

    plaintext = b''
    for block in decrypted_blocks:
        plaintext += block
    return strip_pkcs7_padding(plaintext)
#-----------------------------------------------------------------------------------------------------------------------


def challenge15_oracle(user_input, key, iv):
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

    if ";" in user_input:
        user_input = user_input.replace(";", "%3b")
    if "=" in user_input:
        user_input = user_input.replace("=", "%3d")

    return encrypt_aes128_cbc(bytes(prefix + user_input + suffix, "ascii"), key, iv)
#-----------------------------------------------------------------------------------------------------------------------


def check_admin(test_string):
    if ";admin=true;" in test_string:
        return True
    else:
        return False
#-----------------------------------------------------------------------------------------------------------------------


#todo: this.
def tamper(key, iv):
    cipher = (challenge15_oracle("===hiii;;;;;ii", key, iv))
    return cipher

#-----------------------------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------------------------

if __name__ == '__main__':
    key = generateRandom16bytes()
    iv = generateRandom16bytes()

    cipher = tamper(key, iv)
    print(cipher)

    plain = decrypt_aes128_cbc(cipher, key, iv)
    print(plain)

    is_admin = check_admin(str(plain))
    if is_admin:
        print("\n***SUCCESS***")
    else:
        print("\n===FAIL===")
