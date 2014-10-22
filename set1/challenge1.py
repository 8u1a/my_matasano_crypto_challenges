__author__ = 'christianbuia'



#challenge1
def b64_encode_hexstring(hexstring):
    import base64
    import binascii
    return base64.b64encode(binascii.unhexlify(hexstring))

input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

print(b64_encode_hexstring(input_string))