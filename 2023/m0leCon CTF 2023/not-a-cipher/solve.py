ciphertext_encoded = "59b9587b995a03c653fa9849a2746dbaba5fd6ad58089c04e472474d7442f7cd5840bc03e1bf462dce4a876c452dab0dd4fc144bcb13b38b6c91c404"
plaintext = "[ehy watch d1z](https://www.youtube.com/watch?v=FH9yt8qTACw)"
nonce = 909929503

def decode(s):
    return [int(s[i] + s[i + 1], 16) for i in range(0, len(s), 2)]

def xor_list(a, b):
    return [x ^ y for x, y in zip(a, b)]

ciphertext_list = decode(ciphertext_encoded)
target = xor_list(ciphertext_list, [ord(c) for c in plaintext])

def get_ch(x, y):
    return chr((x << 8 | y) >> 4 & 0b111111)

codes = ''.join([get_ch(target[i], target[i + 1]) + chr(target[i + 2]) for i in range(0, len(target), 3)])
codes_list = [codes[i:i+3][::-1] for i in range(0, len(codes), 3)]

mapping = {
    '0-0' : 0,
    '+0+' : 0,
    '0-+' : 1,
    '+-0' : 2,
    '00+' : 3,
    '--0' : 3,
    '-+0' : 4,
    '0++' : 5,
    '-00' : 5,
    '-++' : 6,
    '--+' : 6,
    '-0+' : 7,
    '0--' : 8,
    '+00' : 8,
    '---' : 9,
    '+-+' : 9,
    '+--' : 10,
    '++-' : 10,
    '+0-' : 11,
    '+++' : 12,
    '-+-' : 12,
    '0+0' : 13,
    '-0-' : 13,
    '0+-' : 14,
    '00-' : 15,
    '++0' : 15
}

print("codes = ", codes_list)

bits = [mapping[x] if x in mapping else -1 for x in codes_list]
bits.remove(-1)
bits = ''.join([bin(x)[2:].zfill(4) for x in bits])

def rollback(x):
    v = (ord(x[2]) - ord('0')) ^ \
        (ord(x[3]) - ord('0')) ^ \
        (ord(x[6]) - ord('0')) ^ \
        (ord(x[7]) - ord('0')) ^ \
        (ord(x[8]) - ord('0')) ^ \
        (ord(x[16]) - ord('0')) ^ \
        (ord(x[22]) - ord('0')) ^ \
        (ord(x[23]) - ord('0')) ^ \
        (ord(x[26]) - ord('0')) ^ \
        (ord(x[30]) - ord('0')) ^ \
        (ord(x[41]) - ord('0')) ^ \
        (ord(x[42]) - ord('0')) ^ \
        (ord(x[43]) - ord('0')) ^ \
        (ord(x[46]) - ord('0')) ^ \
        (ord(x[47]) - ord('0')) ^ \
        (ord(x[48]) - ord('0'))
    return chr(ord('0') + v)

def feedback(x):
    v = (ord(x[0]) - ord('0')) ^ \
        (ord(x[2]) - ord('0')) ^ \
        (ord(x[3]) - ord('0')) ^ \
        (ord(x[6]) - ord('0')) ^ \
        (ord(x[7]) - ord('0')) ^ \
        (ord(x[8]) - ord('0')) ^ \
        (ord(x[16]) - ord('0')) ^ \
        (ord(x[22]) - ord('0')) ^ \
        (ord(x[23]) - ord('0')) ^ \
        (ord(x[26]) - ord('0')) ^ \
        (ord(x[30]) - ord('0')) ^ \
        (ord(x[41]) - ord('0')) ^ \
        (ord(x[42]) - ord('0')) ^ \
        (ord(x[43]) - ord('0')) ^ \
        (ord(x[46]) - ord('0')) ^ \
        (ord(x[47]) - ord('0'))
    return chr(ord('0') + v)

print("bits = ", bits)

# because 0x40 = 0b1000000, the last 7 bits are known. Then the 48 - 7 bits are to be calculated
for i in range(48 - 7):
    c = rollback('?' + bits)
    bits = c + bits

print("recovered bits = ", bits)
lfsr = int(bits[:48], 2)
print("lfsr =", hex(lfsr))
k = lfsr ^ nonce
print("k =", hex(k))
