__author__ = 'christianbuia'
import binascii

def multibyte_xor_hexstrings(bs, key):

    count=0
    decoded_bytes = []
    for b in bs:
        decoded_bytes.append(b^key[count % len(key)])
        count+=1
    return bytearray(decoded_bytes)

text1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

key = "ICE"
key = bytes(key, "ascii")
xorred = multibyte_xor_hexstrings(bytes(text1, "ascii"), key)

print(binascii.hexlify(xorred))

#0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f