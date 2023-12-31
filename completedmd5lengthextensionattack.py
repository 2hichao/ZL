# import struct

# def left_rotate(val, n):
#     return ((val << n) & 0xFFFFFFFF) | (val >> (32 - n))

# def md5(message):
#     # Initialize variables
#     a = 0x67452301
#     b = 0xEFCDAB89
#     c = 0x98BADCFE
#     d = 0x10325476

#     # Pre-processing: padding the message
#     original_length = len(message)
#     # byte x80
#     message += b'\x80'
#     while len(message) % 64 != 56:
#         message += b'\x00'
#     # 'Q' specifies that a 64-bit (8-byte) unsigned long long integer should be packed
#     message += struct.pack('<Q', original_length * 8)

#     # Process the message in 512-bit blocks, 64 is step
#     for i in range(0, len(message), 64):
#         block = message[i:i + 64]
#         # 16 little-endian unsigned integers, an integer is typically represented using 4 bytes (32 bits)
#         x = list(struct.unpack('<16I', block))

#         aa = a
#         bb = b
#         cc = c
#         dd = d
#         # Round 1
#         for j in range(0, 16):
#             F = (b & c) | ((~b) & d)
#             g = j
#             temp = d
#             d = c
#             c = b
#             b = b + left_rotate((a + F + x[j] + 0xD76AA478) & 0xFFFFFFFF, 7)
#             a = temp

#         # Round 2
#         for j in range(16, 32):
#             F = (d & b) | ((~d) & c)
#             g = (5 * j + 1) % 16
#             temp = d
#             d = c
#             c = b
#             b = b + left_rotate((a + F + x[g] + 0xE8C7B756) & 0xFFFFFFFF, 12)
#             a = temp

#         # Round 3
#         for j in range(32, 48):
#             F = (b ^ c ^ d)
#             g = (3 * j + 5) % 16
#             temp = d
#             d = c
#             c = b
#             b = b + left_rotate((a + F + x[g] + 0x242070DB) & 0xFFFFFFFF, 17)
#             a = temp

#         # Round 4
#         for j in range(48, 64):
#             F = (c ^ (b | (~d)))
#             g = (7 * j) % 16
#             temp = d
#             d = c
#             c = b
#             b = b + left_rotate((a + F + x[g] + 0xC1BDCEEE) & 0xFFFFFFFF, 22)
#             a = temp

#         a = (a + aa) & 0xFFFFFFFF
#         b = (b + bb) & 0xFFFFFFFF
#         c = (c + cc) & 0xFFFFFFFF
#         d = (d + dd) & 0xFFFFFFFF

#     result = struct.pack('<4I', a, b, c, d)
#     return result.hex()


# # In the context of MD5, the MD5 hash is a 32-character hexadecimal string, 
# # and each 8-character segment represents a 32-bit integer (A, B, C, and D). 
# # To extract these integers from the hash, 
# # you use struct.unpack and then use [0] to get the first integer (A) from the tuple.
# # use for extension attack, it is contunue to pad
# def compute_magic_number(md5str):
#     # why [0], the initial state of the hash function consists of four 32-bit variables: A, B, C, and D.
#     # IT Is a list [1,2,3,4]
#     A = struct.unpack("I", bytes.fromhex(md5str[0:8]))[0]
#     B = struct.unpack("I", bytes.fromhex(md5str[8:16]))[0]
#     C = struct.unpack("I", bytes.fromhex(md5str[16:24]))[0]
#     D = struct.unpack("I", bytes.fromhex(md5str[24:32]))[0]
#     return A, B, C, D
#     # print(A)


#     # def extension_attack(self, md5str, str_append, lenth):
#     #     self.compute_magic_number(md5str)
#     #     p = self.padding(lenth)
#     #     padding_msg = self.padding( len(str_append), lenth + len(p) + len(str_append) )
#     #     self.md5_iter(str_append + padding_msg)
#     #     return self.hexdigest()

# def extension_attack(md5str, str_append, lenth):
#     A, B, C, D = compute_magic_number(md5str)
#     original_length = len(str_append)
#     str_append += b'\x80'
#     while len(str_append) % 64 != 56:
#         str_append += b'\x00'
#     str_append += struct.pack('<Q', (original_length + 64) * 8)

#     # Process the message in 512-bit blocks, 64 is step
#     for i in range(0, len(str_append), 64):
#         block = str_append[i:i + 64]
#         x = list(struct.unpack('<16I', block))

#         AA = A
#         BB = B
#         CC = C
#         DD = D
#         for j in range(0, 64):  # Perform all four rounds
#             if 0 <= j < 16:
#                 F = (B & C) | ((~B) & D)
#                 g = j
#             elif 16 <= j < 32:
#                 F = (D & B) | ((~D) & C)
#                 g = (5 * j + 1) % 16
#             elif 32 <= j < 48:
#                 F = B ^ C ^ D
#                 g = (3 * j + 5) % 16
#             else:
#                 F = C ^ (B | (~D))
#                 g = (7 * j) % 16

#             temp = D
#             D = C
#             C = B
#             B = B + left_rotate((A + F + x[g] + 0x100000000) & 0xFFFFFFFF, [7, 12, 17, 22][j // 16])
#             A = temp

#         # Update A, B, C, and D
#         A = (A + AA) & 0xFFFFFFFF
#         B = (B + BB) & 0xFFFFFFFF
#         C = (C + CC) & 0xFFFFFFFF
#         D = (D + DD) & 0xFFFFFFFF

#     result = struct.pack('<4I', A, B, C, D)
#     return result.hex()


# input_string = "Hello, World!"
# input_bytes = input_string.encode('utf-8')
# md5str = md5(b'Hello, world!')
# print(md5str)




# # md5_hash = md5(input_bytes)
# # # print("MD5 Hash:", md5_hash)

# # # Your known MD5 hash (replace this with the hash you want to extend)
# # known_md5_hash = "e6ea276b1d93418f3db7c2b92759b4d7"
# # print(known_md5_hash)
# # # Convert the MD5 hash to bytes
# # known_md5_bytes = bytes.fromhex(known_md5_hash)

# # # Length of the original message (you need to know this, or you can estimate it)
# # original_message_length = len("Hello, World!".encode('utf-8'))

# # # Padding to match the block size (64 bytes)
# # padding = b'\x80' + b'\x00' * ((64 - (original_message_length + 1 + 8)) % 64)

# # # Length in bits (original message length in bytes * 8)
# # length_in_bits = original_message_length * 8

# # # Append the known MD5 hash bytes, padding, and additional data
# # extended_data = "AdditionalData".encode('utf-8')

# # # Extend the MD5 hash
# # extended_md5_hash = known_md5_bytes + padding + struct.pack('<Q', length_in_bits) + extended_data

# # # Compute the MD5 hash of the extended data
# # extended_md5_result = md5(extended_md5_hash)

# # print("Extended MD5 Hash:", extended_md5_result)




import hashlib

def md5(message):
    # Create an MD5 hash object
    md5_hash = hashlib.md5()

    # Update the hash object with the input message
    md5_hash.update(message)

    # Get the hexadecimal representation of the hash
    result = md5_hash.hexdigest()

    return result

# Example usage:
message = b'Hello, world!'
hashed_message = md5(message)
print("MD5 Hash:", hashed_message)



# length extension attack
# initialize the md5
import hashpumpy
original_hash = '65a8e27d8879283831b664bd8b7f0ad4'
original_length = 13
new_message = b'&admin=true'
new_hash, forged_message = hashpumpy.hashpump(original_hash, b'', new_message, original_length)
print("New Hash:", new_hash)
print("Forged Message:", forged_message)
