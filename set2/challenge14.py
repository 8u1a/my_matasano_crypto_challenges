__author__ = 'christianbuia'

import random
from Crypto.Cipher import AES
import base64


def pkcs7_padding(message_bytes, block_size):

    pad_length = block_size - (len(message_bytes) % block_size)
    if pad_length != block_size:
        for i in range(0, pad_length):
            message_bytes += bytes([pad_length])

    return message_bytes
#-----------------------------------------------------------------------------------------------------------------------


def generateRandom16bytes():
    ints = []
    for i in range(16):
        ints.append(random.randint(0,255))
    return bytes(ints)
#-----------------------------------------------------------------------------------------------------------------------


#always 16 bytes
def encrypt_aes128(message, key):
    decobj = AES.new(key, AES.MODE_ECB)
    return decobj.encrypt(pkcs7_padding(message, 16))
#-----------------------------------------------------------------------------------------------------------------------


#attempt to detect ECB by looking for identical blocks
def detectEBC(cipher, block_size):
    blocks = []

    for i in range(int(len(cipher)/block_size)):
        blocks.append(cipher[i*block_size:i*block_size+block_size])

    #detecting if dups exist: http://stackoverflow.com/questions/9835762/find-and-list-duplicates-in-python-list
    if (len(set([x for x in blocks if blocks.count(x) > 1]))) > 0:
        return True
    else:
        return False
#-----------------------------------------------------------------------------------------------------------------------


def ecb_oracle(mytext, plaintext):

    #using the same prefix scheme as used in challenge 11 since the spec is pretty broad.
    plaintext_prefix = bytes([random.randint(0, 255) for i in range(random.randint(5, 10))])

    cipher = encrypt_aes128(plaintext_prefix + mytext + plaintext, global_key)
    return cipher
#-----------------------------------------------------------------------------------------------------------------------


#detect oracle is ecb by feeding the oracle with homogeneous plaintext with length equal to exactly 4x the block length,
#then comparing the 2nd & 3rd cipher blocks.  identical cipher blocks indicate the oracle generates ecb ciphers.
#using blocks 2 & 3 in case of random prefixes (of size less than block size) prepended to the plaintext by the oracle
def detect_oracle_is_ecb(oracle_func, block_size):
    ints = [ord("A") for x in range(block_size*4)]
    cipher = oracle_func(bytes(ints), bytes("", "ascii"))

    if cipher[block_size:block_size*2-1] == cipher[block_size*2:block_size*3-1]:
        return True
    else:
        return False

#-----------------------------------------------------------------------------------------------------------------------


def detect_plaintext_padding_size(oracle_func, plaintext, block_size):

    count = 0
    mytext = b""
    observed_blocks = None
    while True:
        cipher = oracle_func(mytext, plaintext)
        next_observed_blocks = len(cipher) / block_size
        if observed_blocks != None and observed_blocks < next_observed_blocks:
            break
        observed_blocks = next_observed_blocks
        mytext += bytes("A", "ascii")
        count += 1
    return (count - 1)
#-----------------------------------------------------------------------------------------------------------------------


def return_sorted_counts_of_lengths(oracle_func, attack_array, plaintext, num_runs=100):
    lengths = []

    for i in range(num_runs):
        l = len(oracle_func(attack_array, plaintext))
        if l not in lengths:
            lengths.append(l)
    return sorted(lengths)

#-----------------------------------------------------------------------------------------------------------------------


#this function turns out to be a waste of time, but keeping it around in case i ever need to calc this.
#determined that i can't calculate the absolute min and max if i don't know the size of the plaintext (only the delta)
#which i am assuming i won't know for this challenge
def find_prefix_delta(oracle_func, plaintext, block_size):
    #we want to find an attack array that results in variable lengths of the cipher text (state 1)
    #we can use that attack array by incrementing a byte at a time til we find an attack array of one len (state 2)
    #we then increment the attack array.
    #when we find one of multiple len, the delta between state 2 and now gives the delta of min and max.
    #this is state 3.
    bounds_count = 0
    bounds_state = 0
    state_2_len = None
    min_max_delta = None
    while True:
        bounds_count += 1
        #first we will find an attack array that yields variably sized cipher texts
        ints = [ord("A") for i in range(bounds_count)]
        bounds_attack_array = bytes(ints)
        #undetermined
        if bounds_state == 0:
            if len(return_sorted_counts_of_lengths(oracle_func, bounds_attack_array, plaintext)) == 1:
                pass
            else:
                bounds_state = 1
            continue

        #variable-length ciphers - looking for the first mono-length
        if bounds_state == 1:
            if len(return_sorted_counts_of_lengths(oracle_func, bounds_attack_array, plaintext)) == 1:
                bounds_state = 2
                state_2_len = len(bounds_attack_array)
            else:
                pass
            continue

        #mono-length ciphers - looking for the first variable length to show us what we subtract from the blocksize
        #to arrive at the delta (delta = blocksize - (length - state 2 length)
        if bounds_state == 2:
            if len(return_sorted_counts_of_lengths(oracle_func, bounds_attack_array, plaintext)) == 1:
                pass
            else:
                bounds_state = 3
                #this number will give me the delta between min and max
                min_max_delta = block_size - (len(bounds_attack_array) - state_2_len)
                break
            continue

    return min_max_delta
#-----------------------------------------------------------------------------------------------------------------------


def crack_ecb(oracle_func, plaintext):

    #detect block size by determining the delta of the first jump in cipher size as the plaintext size increases
    block_size = None
    cipher_size = len(oracle_func(b"A", plaintext))
    size_count = 1
    while True:
        ints = [ord("A") for i in range(size_count)]
        size_attack_array = bytes(ints)
        next_cipher_size = len(oracle_func(size_attack_array, plaintext))
        if next_cipher_size > cipher_size:
            block_size = next_cipher_size - cipher_size
            break
        size_count += 1

    #not sure i need this
    prefix_delta = find_prefix_delta(oracle_func, plaintext, block_size)

    size_of_unaltered_cipher = len(oracle_func(b"", plaintext))
    number_of_blocks = int(size_of_unaltered_cipher / block_size)

    #the solved plain text we accumulate and return
    solved_plain_text = b""

    for block_number in range(number_of_blocks):

        #generally we do a full block_size cycle of attack arrays...
        #unless it's the last block, in which case we subtract padding.
        if block_number == number_of_blocks - 1:
            iters = block_size - padding_size
        else:
            iters = block_size

        for byte_number in range(iters):

            #generate a homogeneous string of bytes that is of size block_size - 1 - (the number of solved bytes)
            ints = [ord("A") for i in range(block_size-1-byte_number)]
            attack_array = bytes(ints)

            just_short_array = attack_array + solved_plain_text

            last_byte_dict = {}
            #ordinal for all ascii (0-127)
            for i in range(0, 127+1):
                last_byte_dict[i] = oracle_func(just_short_array, bytes([i]))

            cipher = oracle_func(attack_array, plaintext)

            for i in last_byte_dict.__iter__():
                if last_byte_dict[i] == cipher[:block_size*(block_number + 1)]:
                    solved_plain_text += bytes([i])

    return solved_plain_text
#***********************************************************************************************************************

if __name__ == '__main__':
    global global_key
    global_key = generateRandom16bytes()

    b64_unknown_string = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK""".replace("\n", "")

    #prep the plaintext, though we don't want to know what it is yet
    #(we are going to use the oracle to crack encrypted versions of the plaintext)
    unknown_string = base64.b64decode(b64_unknown_string)
    challenge_plaintext = bytes(unknown_string)

    print(crack_ecb(ecb_oracle, challenge_plaintext))

