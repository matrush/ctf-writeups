from present import Present
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes
from itertools import product
import os


class CTRMode:
    def __init__(self, key, nonce=None):
        self.key = key  # 20bytes
        self.cipher = DoubleRoundReducedPresent(key)
        if None == nonce:
            nonce = os.urandom(self.cipher.block_size // 2)
        self.nonce = nonce  # 4bytes

    def XorStream(self, data):
        output = b""
        counter = 0
        for i in range(0, len(data), self.cipher.block_size):
            keystream = self.cipher.encrypt(
                self.nonce + counter.to_bytes(self.cipher.block_size // 2, "big")
            )
            if b"" == keystream:
                exit(1)

            if len(data) < i + self.cipher.block_size:
                block = data[i : len(data)]
            block = data[i : i + self.cipher.block_size]
            block = strxor(keystream[: len(block)], block)

            output += block
            counter += 1
        return output

    def encrypt(self, plaintext):
        return self.XorStream(plaintext)

    def decrypt(self, ciphertext):
        return self.XorStream(ciphertext)


class DoubleRoundReducedPresent:
    def __init__(self, key):
        self.block_size = 8
        self.key_length = 160  # bits
        self.round = 16
        self.cipher0 = Present(key[0:10], self.round)
        self.cipher1 = Present(key[10:20], self.round)

    def encrypt(self, plaintext):
        if len(plaintext) > self.block_size:
            print(
                "Error: Plaintext must be less than %d bytes per block"
                % self.block_size
            )
            return b""
        return self.cipher1.encrypt(self.cipher0.encrypt(plaintext))

    def decrypt(self, ciphertext):
        if len(ciphertext) > self.block_size:
            print(
                "Error: Ciphertext must be less than %d bytes per block"
                % self.block_size
            )
            return b""
        return self.cipher0.decrypt(self.cipher1.decrypt(ciphertext))


if __name__ == "__main__":
    BLOCK_SIZE = 8
    LEN = 10
    ciphertext_hex = "3201339d0fcffbd152f169ddcb8349647d8bc36a73abc4d981d3206f4b1d98468995b9b1c15dc0f0"
    nonce_hex = "32e10325"
    nonce = int(nonce_hex, 16).to_bytes(BLOCK_SIZE // 2, "big")
    counter = 0
    plaintext1 = nonce + counter.to_bytes(BLOCK_SIZE // 2, "big")
    ciphertext1 = strxor(
        long_to_bytes(int(ciphertext_hex[0:16], 16)), "LINECTF{".encode()
    )

    # self.cipher0.encrypt(plaintext1) == self.cipher1.decrypt(ciphertext1)
    hash1 = set()
    hash2 = set()
    for key_mask in range(4 ** LEN):
        key = ""
        for i in range(LEN):
            key += chr(ord("0") + key_mask % 4)
            key_mask //= 4
        cipher = Present(key.encode(), 16)
        hash1.add(cipher.decrypt(ciphertext1))
        hash2.add(cipher.encrypt(plaintext1))

    intersect = hash1 & hash2
    assert len(intersect) == 1
    ciphertext1_middle = list(intersect)[0]
    assert ciphertext1_middle == b"\x9f?An\x87\xac\xba\xe1"

    cand_key = ["".join(key) for key in product("0123", repeat=LEN)]
    for key in cand_key:
        cipher = Present(key.encode(), 16)
        if cipher.encrypt(plaintext1) == ciphertext1_middle:
            key1 = key
            assert key1 == "3201323020"
        if cipher.encrypt(ciphertext1_middle) == ciphertext1:
            key2 = key
            assert key2 == "2123003302"
        if key1 and key2:
            break
    key = key1 + key2
    assert key == "32013230202123003302"
    cipher = CTRMode(key.encode(), nonce=nonce)
    flag = cipher.decrypt(long_to_bytes(int(ciphertext_hex, 16))).decode()
    print(flag)
    # LINECTF{|->TH3Y_m3t_UP_1n_th3_m1ddl3<-|}
    assert flag == "LINECTF{|->TH3Y_m3t_UP_1n_th3_m1ddl3<-|}"
