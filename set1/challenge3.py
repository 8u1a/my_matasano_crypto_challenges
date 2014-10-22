__author__ = 'christianbuia'
import binascii

def fixed_xor_hexstrings(hexstring1, key):
    import binascii
    bytes1=binascii.unhexlify(hexstring1)
    decoded = ""
    for byte in bytes1:
        decoded+=chr(byte^key)
    return decoded


def evaluate_as_english(message):

    #first stage, we get rid of anything that has nonprintables
    for s in message:
        if ord(s) < 32 or ord(s) > 126:
            return False

    #second stage, we get rid of anything that doesn't seem to have
    #space-separated words of reasonable length.
    split_tokens = message.split(" ")
    if len(split_tokens) < len(message) / 10:
        return False

    return True

input_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

input_bytes = binascii.unhexlify(input_string)
print(input_bytes)

possible_matches = 0

for i in range(256):
    message = fixed_xor_hexstrings(input_string, i)
    if evaluate_as_english(message):
        possible_matches+=1
        print(i)
        print(hex(i))
        print(message)
print("possible matches " + str(possible_matches))