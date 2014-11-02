__author__ = 'christianbuia'
import binascii

def fixed_xor_hexstrings(hexstring1, key):
    import binascii
    bytes1=binascii.unhexlify(hexstring1)
    decoded = ""
    for byte in bytes1:
        decoded+=chr(byte^key)
    return decoded

"""
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
"""
def evaluate_as_english(message, ratio_common_printables, ratio_spaces_to_letters):

    #count the number of common printables vs non-common printbables
    count_cp = 0
    count_ncp = 0
    count_letters = 0
    count_spaces = 0
    for m in message:
        letters=False
        numbers=False
        punct = False
        m = ord(m)
        if m > 64 and m < 123:
            letters = True
            count_letters+=1
        if m > 47 and m < 58:
            numbers=True
        if m==32 or m==33 or m==34 or m==40 or m==41 or m==46 or m==63:
            punct = True
            if m==32:
                count_spaces+=1

        if letters or numbers or punct:
            count_cp+=1
        else:
            count_ncp+=1

    if count_cp / (count_cp + count_ncp) > ratio_common_printables:
        if count_spaces / (count_letters + count_spaces) > ratio_spaces_to_letters:
            return True
    else:
        return False





input_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

input_bytes = binascii.unhexlify(input_string)
print(input_bytes)

possible_matches = 0

for i in range(256):
    message = fixed_xor_hexstrings(input_string, i)
    if evaluate_as_english(message, .9, .1):
        possible_matches+=1
        print(i)
        print(hex(i))
        print(message)
print("possible matches " + str(possible_matches))