
from bitarray import bitarray
import struct

def md5(msg):
    # Constants/Helper Functions
    F = lambda x, y, z: (x & y) | ((~x) & z)
    G = lambda x, y, z: (x & z) | (y & (~z))
    H = lambda x, y, z: (x ^ y ^ z)
    I = lambda x, y, z: (y ^ (x | (~z)))
    ROT = lambda x, n: ((x << n) | (x >> (32 - n)))
    HEXSTR = lambda x: '{0:08x}'.format(struct.unpack('<I', struct.pack('>I',x))[0])
    ADD = lambda x, y: (x + y) % (1 << 32)
    s = [7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
         5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
         4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
         6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
    #Precomputed values, K[i] = floor(2^32 * sin(i+1))
    K = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]
    #initial register values
    a0 =0x67452301
    b0 =0xefcdab89
    c0 =0x98badcfe
    d0 =0x10325476

    #Message Padding
    bitString = bitarray(endian='big')
    bitString.frombytes(msg)
    originalLength = len(bitString)
    bitString.append(1)
    while bitString.length() % 512 != 448:
        bitString.append(0)
    bitString = bitarray(bitString, endian='little')
    bitString  += '{0:064b}'.format(originalLength)[::-1]

    #Main Loop
    for j in range(len(bitString) // 512):
        currBlock = bitString[512*j:512*(j+1)]
        M = [int.from_bytes(currBlock[x*32:(x+1)*32].tobytes(),byteorder='little') for x in range(16)]
        A,B,C,D = a0,b0,c0,d0
        for i in range(64):
            if i < 16:
                f = F(B,C,D)
                g = i 
            elif i < 32:
                f = G(B,C,D)
                g = ((5 * i) + 1) % 16
            elif i < 48:
                f = H(B,C,D)
                g = ((3 * i) + 5) % 16
            else:
                f = I(B,C,D)
                g = (7*i) % 16
            f = (f + A + K[i] + M[g]) % (1 << 32)
            A = D 
            D = C
            C = B 
            B = ADD(ROT(f,s[i]), B)
        a0 = ADD(a0, A) 
        b0 = ADD(b0, B) 
        c0 = ADD(c0, C) 
        d0 = ADD(d0, D) 
    return HEXSTR(a0) + HEXSTR(b0) + HEXSTR(c0) + HEXSTR(d0)

if __name__ == "__main__":
    tests = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"]
    expected = ["d41d8cd98f00b204e9800998ecf8427e", 
    "0cc175b9c0f1b6a831c399e269772661",
    "900150983cd24fb0d6963f7d28e17f72",
    "f96b697d7cb7938d525a2f31aaf161d0",
    "c3fcd3d76192e4007dfb496cca67e13b",
    "d174ab98d277d9f5a5611c2c9f419d9f",
    "57edf4a22be3c955ac49da2e2107b67a"
    ]
    passed = True
    for i in range(len(tests)):
        tmp = md5(tests[i].encode('utf-8'))
        if tmp != expected[i]:
            print("Test Failure")
            print(tmp,tests[i])
            print(expected[i])
            passed = False
    if passed:
        print("All tests passed :)")
