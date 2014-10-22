__author__ = 'christianbuia'

import binascii
import sys
import base64

def hamming_distance_two_hexstrings(hexstring1, hexstring2):

    distance = 0

    if len(hexstring1) != len(hexstring2):
        sys.stderr.write("unexpected: length of compared strings don't match. exiting.\n")
        return False

    bytes1 = binascii.unhexlify(hexstring1)
    bytes2 = binascii.unhexlify(hexstring2)

    bin_string1 = ""
    bin_string2 = ""

    for i in range(len(bytes1)):

        #taking [2:] to convert 0b1110100 to 1110100
        temp_bin1 = bin(bytes1[i])[2:]
        temp_bin2 = bin(bytes2[i])[2:]

        while len(temp_bin1) < 8:
            temp_bin1 = "0" + temp_bin1

        while len(temp_bin2) < 8:
            temp_bin2 = "0" + temp_bin2

        bin_string1 += temp_bin1
        bin_string2 += temp_bin2

    for i in range(len(bin_string1)):
        if bin_string1[i] != bin_string2[i]:
            distance += 1

    return distance
#--------------------------------------------------------------------------
def multibyte_xor_hexstrings(hexstring1, key):

    import binascii
    bytes1=binascii.unhexlify(hexstring1)

    decoded = ""
    count = 0
    for byte in bytes1:
        decoded+=chr(byte ^ ord(key[count % len(key)]))
        count+=1

    return decoded
#--------------------------------------------------------------------------

def fixed_xor_hexstrings(hexstring1, key):

    bytes1=binascii.unhexlify(hexstring1)
    decoded = ""
    for byte in bytes1:
        #print(byte)
        #print(key)
        decoded += chr(byte^key)
    return decoded
#--------------------------------------------------------------------------


def evaluate_as_english(message):

    #first stage, we get rid of anything that has nonprintables
    #for s in message:
    #    if ord(s) < 32 or ord(s) > 126:
    #        return False

    #second stage, we get rid of anything that doesn't seem to have
    #space-separated words of reasonable length.
    split_tokens = message.split(" ")
    if len(split_tokens) < len(message) / 10:
        return False

    return True
#--------------------------------------------------------------------------


def solve_block(block_data):
    for i in range(256):
        message = fixed_xor_hexstrings(block_data, i)
        if evaluate_as_english(message):
            return i
    return False
#--------------------------------------------------------------------------


def solve_challenge(b64_crypt):

    ciphertext = base64.b64decode(b64_crypt)

    #dictionary of hamming distances in the form {'keysize':'distance'}
    keysize_hamming_distances = {}

    for x in range(40):
        if x < 2:
            continue

        distances = []

        #compute the average normalized hamming distance given keysize x
        for i in range((len(ciphertext) // x) - 1):
            h = hamming_distance_two_hexstrings(binascii.hexlify(ciphertext[i*x:i*x+x]), binascii.hexlify(ciphertext[(i+1)*x:(i+1)*x+x]))
            h_normal = h / x
            distances.append(h_normal)
        keysize_hamming_distances[x] = sum(distances)/len(distances)

    keysize_candidates_size = 1
    keysize_candidates = []
    c = 0

    #determine candidate keysizes
    for v in sorted(keysize_hamming_distances.values()):
        for i in keysize_hamming_distances.keys():
            if keysize_hamming_distances[i] == v:
                keysize_candidates.append(i)
                c += 1
                continue
        if c < keysize_candidates_size:
            continue
        else:
            break

    #for each key size, attempt to solve the multibyte key
    for k_candidate in keysize_candidates:
        standard_blocks = [ciphertext[x:x+k_candidate] for x in range(0, len(ciphertext), k_candidate)]
        transposed_blocks = []

        #init the transposed blocks
        for i in range(k_candidate):
            transposed_blocks.append(b"")

        for current_std_block in standard_blocks:
            for i in range(len(current_std_block)):
                transposed_blocks[i] = b"".join([transposed_blocks[i], bytes([current_std_block[i]])])

        #guess xor bytes
        guessed_xor_keys = []
        for b in transposed_blocks:
            guessed_xor_keys.append(solve_block(binascii.hexlify(b)))

        #create key
        key = b""
        for x in guessed_xor_keys:
            key = b"".join([key, bytes([x])])

        #print decrypted blocks
        count = 0
        for block in standard_blocks:
            print(block)
            if count < len(standard_blocks)-1:
                print(multibyte_xor_hexstrings(binascii.hexlify(block), key))
                count+=1
    return True
#--------------------------------------------------------------------------

#hamming function test
#string1 = "this is a test"
#string2 = "wokka wokka!!!"
#print(hamming_distance_two_hexstrings(binascii.hexlify(bytes(string1, "ascii")), binascii.hexlify(bytes(string2, "ascii"))))



b64_crypt = """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""".replace("\n", "")

solve_challenge(b64_crypt)