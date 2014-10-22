__author__ = 'christianbuia'



def fixed_xor_hexstrings(hexstring1, hexstring2):
    import binascii
    bytes1=binascii.unhexlify(hexstring1)
    bytes2=binascii.unhexlify(hexstring2)

    outbytes = [hex(a ^ b) for a, b in zip(bytes1, bytes2)]
    return bytes("".join(outbytes).replace("0x", ""), "ASCII")


input1 = "1c0111001f010100061a024b53535009181c"
input2 = "686974207468652062756c6c277320657965"

print(fixed_xor_hexstrings(input1, input2))