# S[0] ^ S[2] = Share[1][24:32] ^ Share[4][24:32]
# S[1] ^ S[3] = Share[1][16:24] ^ Share[4][16:24]
# S[3] ^ S[0] = Share[1][0:8] ^ Share[4][0:8]
# Get S[0] - S[3], then get R[0] - R[3]


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))


with open("./Share1", "rb") as f:
    Share1 = f.read()
    f.close()

with open("./Share4", "rb") as f:
    Share4 = f.read()
    f.close()

S0 = b"LINECTF{"
S2 = xor(xor(Share1[24:32], Share4[24:32]), S0)
S3 = xor(xor(Share1[0:8], Share4[0:8]), S0)
S1 = xor(xor(Share1[16:24], Share4[16:24]), S3)
R0 = xor(Share1[0:8], S0)
R1 = xor(Share4[8:16], S2)
R2 = xor(Share1[16:24], S3)
R3 = xor(Share1[24:32], S2)
FLAG = (S0 + S1 + S2 + S3 + R0 + R1 + R2 + R3).decode()
print(FLAG)
assert FLAG == "LINECTF{Yeah_known_plaintext_is_important_in_xor_based_puzzle!!}"
# LINECTF{Yeah_known_plaintext_is_important_in_xor_based_puzzle!!}
