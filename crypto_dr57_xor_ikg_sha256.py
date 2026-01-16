import copy
import struct
import binascii
import os

#================================================================
#
#                             SHA256                             
#
#----------------------------------------------------------------


F32 = 0xFFFFFFFF

_k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

_h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

def _pad(msglen):
    mdi = msglen & 0x3F
    length = struct.pack('!Q', msglen << 3)

    if mdi < 56:
        padlen = 55 - mdi
    else:
        padlen = 119 - mdi

    return b'\x80' + (b'\x00' * padlen) + length

def _rotr(x, y):
    return ((x >> y) | (x << (32 - y))) & F32

def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def _ch(x, y, z):
    return (x & y) ^ ((~x) & z)

class SHA256:
    _output_size = 8
    blocksize = 1
    block_size = 64
    digest_size = 32

    def __init__(self, m=None):
        self._counter = 0
        self._cache = b''
        self._k = copy.deepcopy(_k)
        self._h = copy.deepcopy(_h)

        self.update(m)

    def _compress(self, c):
        w = [0] * 64
        w[0:16] = struct.unpack('!16L', c)

        for i in range(16, 64):
            s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & F32

        a, b, c, d, e, f, g, h = self._h

        for i in range(64):
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            t2 = s0 + _maj(a, b, c)
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            t1 = h + s1 + _ch(e, f, g) + self._k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & F32
            d = c
            c = b
            b = a
            a = (t1 + t2) & F32

        for i, (x, y) in enumerate(zip(self._h, [a, b, c, d, e, f, g, h])):
            self._h[i] = (x + y) & F32

    def update(self, m):
        if not m:
            return

        self._cache += m
        self._counter += len(m)

        while len(self._cache) >= 64:
            self._compress(self._cache[:64])
            self._cache = self._cache[64:]
        
        return self

    def digest(self):
        r = copy.deepcopy(self)
        r.update(_pad(self._counter))
        data = [struct.pack('!L', i) for i in r._h[:self._output_size]]
        return bytearray().join(data)

    def hexdigest(self):
        return binascii.hexlify(self.digest()).decode('ascii')


#================================================================
#
#                           Interface                
#
#----------------------------------------------------------------

salt = bytearray()
lastHash = bytearray()

def _SetChunkGenerator(gen_seed, gen_salt):
    global salt
    global lastHash
    salt = gen_salt
    lastHash = gen_seed

def _Reset():
    global lastHash
    lastHash = bytearray()

def _Shred():
    global salt
    global lastHash
    i = len(salt)
    while i > 0:
        i -= 1
        salt[i] = 0x00
    i = len(lastHash)
    while i > 0:
        i -= 1
        lastHash[i] = 0x00

def _GetKeyChunk():
    global salt
    global lastHash
    #print(SHA256().update(lastHash + salt).hexdigest())
    lastHash = SHA256().update(lastHash + salt).digest()
    return lastHash

# based on: https://github.com/Dataram57/xorcrypt/blob/master/ikg_sha256.py

def _XOREncryptDecrypt(input_file, output_file):
    data = bytearray()
    encrypted_data = bytearray()
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        while True:
            #Generate Key
            key = _GetKeyChunk()
            key_len = len(key)
            #Read chunk to xor
            data = f_in.read(key_len)
            #check EOF
            if not data:
                break
            #more info
            data_len = len(data)
            #XOR the data
            i = 0
            f = min(data_len, key_len)
            encrypted_data = bytearray()
            while i < f:
                encrypted_data.append(data[i] ^ key[i])
                i += 1
            #Write the encrypted/decrypted data to the output file
            f_out.write(encrypted_data)
    #shred
    i = len(data)
    while i > 0:
        i -= 1
        data[i] = 0x00
    print("Finished")

# based on: https://github.com/Dataram57/xorcrypt/blob/master/xorcrypt.py

#================================================================
#
#                              Main                              
#
#----------------------------------------------------------------

mainKey = bytearray(bytes.fromhex("00"))

def initialize(config):
    mainKey = bytearray(bytes(config["password"], "ascii"))

def end():
    #shred generator
    _Shred()
    #shred main key
    i = len(mainKey)
    while i > 0:
        i -= 1
        mainKey[i] = 0x00

def generate_salt(length=16):
    return os.urandom(length)

def encrypt(file_path, output_path, salt=None):
    if salt != None:
        _SetChunkGenerator(mainKey, bytearray(salt))
    else:
        _SetChunkGenerator(bytearray(), mainKey)
    _XOREncryptDecrypt(file_path, output_path)


def decrypt(file_path, output_path, salt=None):
    return encrypt(file_path, output_path, salt)

