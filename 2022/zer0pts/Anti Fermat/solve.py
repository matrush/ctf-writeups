from Crypto.Util.number import long_to_bytes, isPrime
from gmpy2 import *
n = 0x1ffc7dc6b9667b0dcd00d6ae92fb34ed0f3d84285364c73fbf6a572c9081931be0b0610464152de7e0468ca7452c738611656f1f9217a944e64ca2b3a89d889ffc06e6503cfec3ccb491e9b6176ec468687bf4763c6591f89e750bf1e4f9d6855752c19de4289d1a7cea33b077bdcda3c84f6f3762dc9d96d2853f94cc688b3c9d8e67386a147524a2b23b1092f0be1aa286f2aa13aafba62604435acbaa79f4e53dea93ae8a22655287f4d2fa95269877991c57da6fdeeb3d46270cd69b6bfa537bfd14c926cf39b94d0f06228313d21ec6be2311f526e6515069dbb1b06fe3cf1f62c0962da2bc98fa4808c201e4efe7a252f9f823e710d6ad2fb974949751
c = 0x60160bfed79384048d0d46b807322e65c037fa90fac9fd08b512a3931b6dca2a745443a9b90de2fa47aaf8a250287e34563e6b1a6761dc0ccb99cb9d67ae1c9f49699651eafb71a74b097fc0def77cf287010f1e7bd614dccfb411cdccbb84c60830e515c05481769bd95e656d839337d430db66abcd3a869c6348616b78d06eb903f8abd121c851696bd4cb2a1a40a07eea17c4e33c6a1beafb79d881d595472ab6ce3c61d6d62c4ef6fa8903149435c844a3fab9286d212da72b2548f087e37105f4657d5a946afd12b1822ceb99c3b407bb40e21163c1466d116d67c16a2a3a79e5cc9d1f6a1054d6be6731e3cd19abbd9e9b23309f87bfe51a822410a62
e = 65537

# q = next_prime(p ^ ((1<<1024)-1))
# q = next_prime((1<<1024) - 1 - p))
# p * (2^1024 - 1 - p + k) = n
# p^2 - (2^1024 - 1 + k) * p + n = 0
A = 1
B = -(2 ** 1024 - 1)
C = n

k = 0
while True:
  BB = B - k
  delta = BB * BB - 4 * A * C
  if is_square(delta):
    break
  k += 1

B -= k
delta = B * B - 4 * A * C

p = (-B + isqrt(delta)) // (2 * A)
q = (-B - isqrt(delta)) // (2 * A)

assert isPrime(p) and isPrime(q)
assert q == next_prime(p ^ ((1<<1024)-1))
assert p * q == n

phi = (p - 1) * (q - 1)
d = invert(e, phi)
flag = long_to_bytes(pow(c, d, n)).decode()
print(flag)
# zer0pts{F3rm4t,y0ur_m3th0d_n0_l0ng3r_w0rks.y0u_4r3_f1r3d}
assert 'zer0pts{F3rm4t,y0ur_m3th0d_n0_l0ng3r_w0rks.y0u_4r3_f1r3d}' in flag
