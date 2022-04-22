# Malleable Metal

## Challenge [[Link]](https://ctftime.org/task/20471)
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
import random
import binascii
from secret import flag

e = 3
BITSIZE =  8192
key = RSA.generate(BITSIZE)
n = key.n
flag = bytes_to_long(flag)
m = floor(BITSIZE/(e*e)) - 400
assert (m < BITSIZE - len(bin(flag)[2:]))
r1 = random.randint(1,pow(2,m))
r2 = random.randint(r1,pow(2,m))
msg1 = pow(2,m)*flag + r1
msg2 = pow(2,m)*flag + r2
C1 = Integer(pow(msg1,e,n))
C2 = Integer(pow(msg2,e,n))
print(f'{n = }\n{C1 = }\n{C2 = }')
```

## Solution

From `pow(2, m) * flag + r` pattern and `BITSIZE / (e * e)` we can tell it's a [Coppersmith’s short-pad attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack) via some search.

I used [this](https://github.com/pwang00/Cryptographic-Attacks/blob/master/Public%20Key/RSA/coppersmith_short_pad.sage) sage script to solve it. The default parameters works fine in this case.

## Flag
`crew{l00ks_l1k3_y0u_h4v3_you_He4rd_0f_c0pp3rsm1th_sh0r+_p4d_4tt4ck_th4t_w45n\'t_d1ff1cult_w4s_it?}`

## References
- [Coppersmith’s short-pad attack](https://en.wikipedia.org/wiki/Coppersmith%27s_attack)
- [Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf)
- [Cryptographic Attacks](https://github.com/pwang00/Cryptographic-Attacks)
