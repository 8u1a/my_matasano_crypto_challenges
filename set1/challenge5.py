__author__ = 'christianbuia'
import binascii

def multibyte_xor_hexstrings(hexstring1, key):

    import binascii
    bytes1=binascii.unhexlify(hexstring1)

    decoded = ""
    count = 0
    for byte in bytes1:
        decoded+=chr(byte ^ ord(key[count % len(key)]))
        count+=1

    return decoded

text1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

key = "ICE"
xorred = multibyte_xor_hexstrings(binascii.hexlify(bytes(text1, "ascii")), key)
print(binascii.hexlify(bytes(xorred, "ascii")), key)