__author__ = 'christianbuia'


def pkcs7_padding(message_bytes, block_size):

    pad_length = block_size - (len(message_bytes) % block_size)
    if pad_length != block_size:
        for i in range(0, pad_length):
            message_bytes.append(pad_length)

    return message_bytes

#=======================================================================================================================

print(pkcs7_padding(bytearray("YELLOW SUBMARINE", "utf-8"), 20))
print(pkcs7_padding(bytearray("YELLOW SUBMARINE", "utf-8"), 21))
print(pkcs7_padding(bytearray("WE ALL LIVE IN A YELLOW SUBMARINE", "utf-8"), 20))
print(pkcs7_padding(bytearray("WE ALL LIVE IN A YEL", "utf-8"), 20))