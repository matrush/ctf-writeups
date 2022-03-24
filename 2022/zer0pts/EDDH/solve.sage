from Crypto.Cipher import AES
from Crypto.Util.number import inverse, long_to_bytes
from hashlib import sha256
from pwn import *
import ast

n = 256
p = 64141017538026690847507665744072764126523219720088055136531450296140542176327
a = 362
d = 1
q = 64141017538026690847507665744072764126693080268699847241685146737444135961328
gx = 36618472676058339844598776789780822613436028043068802628412384818014817277300
gy = 9970247780441607122227596517855249476220082109552017755637818559816971965596

def xor(xs, ys):
    return bytes(x^^y for x, y in zip(xs, ys))

def pad(b, l):
    return b + b"\0" + b"\xff" * (l - (len(b) + 1))

def unpad(b):
    l = -1
    while b[l] != 0:
        l -= 1
    return b[:l]

def add(P, Q):
    (x1, y1) = P
    (x2, y2) = Q

    x3 = (x1*y2 + y1*x2) * inverse(1 + d*x1*x2*y1*y2, p) % p
    y3 = (y1*y2 - a*x1*x2) * inverse(1 - d*x1*x2*y1*y2, p) % p
    return (x3, y3)

def mul(x, P):
    Q = (0, 1)
    x = x % q
    while x > 0:
        if x % 2 == 1:
            Q = add(Q, P)
        P = add(P, P)
        x = x >> 1
    return Q

LEN = n // 8 * 2

G = (gx, gy)

while True:
     io = remote("crypto.ctf.zer0pts.com", 10929)
     # sG = (..., ...)
     sG_str = io.readline().strip().decode()
     assert sG_str.startswith('sG = ')
     exec(sG_str)
     io.recvuntil('tG = ')
     # Invalid curve attack, sending (0, y) will get s * t * G == (0, y^s)
     io.sendline('(0, 2)'.encode())
     # Send first message to recover share
     io.sendline(('00' * LEN).encode())
     msg_xor_share = bytes.fromhex(io.recvline().strip().decode())
     msg = b'\0' * (LEN // 2 - 1)
     share = xor(pad(msg, LEN), msg_xor_share)
     # 2 ** s == y % p
     F = IntegerModRing(p)
     y = int.from_bytes(share, 'big')
     s = discrete_log(F(y), F(2))
     # If any byte of hex(share) is \0, the msg will be wrong.
     # We just need to retry if that happens.
     if sG == mul(s, G):
          break
     io.close()

# Send second message to get encrypted flag
flag_msg = xor(pad(b'flag', LEN), share).hex()
io.sendline(flag_msg.encode())
flag_enc_bytes = bytes.fromhex(io.recvline().strip().decode())
assert len(flag_enc_bytes) == LEN
flag_enc = unpad(xor(flag_enc_bytes, share))
aes = AES.new(key=sha256(long_to_bytes(s)).digest(), mode=AES.MODE_ECB)
flag = aes.decrypt(flag_enc).strip(b'\0').decode()
print(flag)
# zer0pts{edwards_what_the_hell_is_this}
assert flag == 'zer0pts{edwards_what_the_hell_is_this}'
