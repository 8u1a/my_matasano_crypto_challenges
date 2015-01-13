__author__ = 'christianbuia'


#rewriting this to add a block of padding for plaintexts that have a length which is a multiple of blocksize
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


testbytes = add_pkcs7_padding(b"hello", 16)
print(strip_pkcs7_padding(testbytes))

testbytes = add_pkcs7_padding(b"0123456789abcdefhello", 16)
print(strip_pkcs7_padding(testbytes))

testbytes = add_pkcs7_padding(b"0123456789abcdef", 16)
print(strip_pkcs7_padding(testbytes))

#in this case, \x02 is part of the unpadded plaintext
testbytes = b"0123456789abcd\x02\x01"
print(strip_pkcs7_padding(testbytes))

#this should fail
testbytes = b"0123456789abcdefhellodearworld\x01\x02"
print(strip_pkcs7_padding(testbytes))
