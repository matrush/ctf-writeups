# r = g^k mod p and s = (k^-1(H(m) + xr)) mod p
# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
# https://neuromancer.sk/std/secg/secp160r1
# https://furutsuki.hatenablog.com/entry/2021/03/21/101039


p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF
a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
E = EllipticCurve(GF(p), (a, b))
G = E(
    0x4A96B5688EF573284664698968C38BB913CBFC82,
    0x23A628553168947D59DCC912042351377AC5FB32,
)
E.set_order(0x0100000000000000000001F4C8F927AED3CA752257)

n = int(E.order())

dataset = []
with open("output.txt") as f:
    for l in f:
        dataset.append([int(x, 16) for x in l.split()])

r, s, k, h = zip(*dataset)
N = 100
rs = [r[i] * inverse_mod(s[i], n) % n for i in range(N)]
hs = [h[i] * inverse_mod(-s[i], n) % n for i in range(N)]

UNKNOWN_BITS = 64
NONCE_MAX = 2 ** 128

M = matrix(QQ, N + 2, N + 2)
M.set_block(0, 0, matrix.identity(N) * n)
M.set_block(N, 0, matrix(QQ, 1, N, rs))
M.set_block(N + 1, 0, matrix(QQ, 1, N, hs))
M[N, N] = NONCE_MAX / n
M[N + 1, N + 1] = NONCE_MAX

L = M.LLL()
for row in list(L):
    current_k = int(abs(row[0]))
    if current_k != 0 and current_k != NONCE_MAX and current_k < NONCE_MAX:
        x = (current_k * s[0] - h[0]) * inverse_mod(r[0], n) % n
        assert (current_k >> UNKNOWN_BITS) << UNKNOWN_BITS in k
        flag = "LINECTF{%s}" % hex(x)
        print(flag)
        # LINECTF{0xd77d10fec685cbe16f64cba090db24d23b92f824}
        assert flag == 'LINECTF{0xd77d10fec685cbe16f64cba090db24d23b92f824}'
