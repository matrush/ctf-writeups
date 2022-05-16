from pwn import *
from Crypto.Util.number import long_to_bytes

p = remote("challs.m0lecon.it", 1753)
p.recvuntil(b'Generating data...\n')
# n =
exec(p.recvline().strip().decode())
# c =
exec(p.recvline().strip().decode())
# e =
exec(p.recvline().strip().decode())
p.recvuntil(b'Choose a value: ')
p.sendline(b"5")
# M =
exec(p.recvline().strip().decode())

# Server gives either ((p - 1) / 2 * (q - 1) / 2) or (p - 1) * (q - 1) / 2
lambda_n = 2 * M

d = pow(e, -1, lambda_n)
m = long_to_bytes(pow(c, d, n))
flag = m.decode()
assert flag == 'ptm{y0u_found_another_w4y_t0_factorize}'
print(flag)
