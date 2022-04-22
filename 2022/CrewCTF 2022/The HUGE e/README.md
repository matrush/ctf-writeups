# The HUGE e

## Challenge [[Link]](https://ctftime.org/task/20470)
> I waited endless hours to do this.
```python
from Crypto.Util.number import getPrime, bytes_to_long, inverse, isPrime
from secret import flag

m = bytes_to_long(flag)

def getSpecialPrime():
    a = 2
    for i in range(40):
        a*=getPrime(20)
    while True:
        b = getPrime(20)
        if isPrime(a*b+1):
            return a*b+1


p = getSpecialPrime()
e1 = getPrime(128)
e2 = getPrime(128)
e3 = getPrime(128)

e = pow(e1,pow(e2,e3))
c = pow(m,e,p)

assert pow(c,inverse(e,p-1),p) == m

print(f'p = {p}')
print(f'e1 = {e1}')
print(f'e2 = {e2}')
print(f'e3 = {e3}')
print(f'c = {c}')
```

## Solution

Per [Euler's totient function](https://en.wikipedia.org/wiki/Euler%27s_totient_function) and [Euler’s theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem), we have `m^e1^e2^e3 % p = m^(e1^e2^e3 % (p - 1)) % p`.

Per testing on [factordb](http://factordb.com/index.php?query=127557933868274766492781168166651795645253551106939814103375361345423596703884421796150924794852741931334746816404778765897684777811408386179315837751682393250322682273488477810275794941270780027115435485813413822503016999058941190903932883822), `p - 1` is actually smooth and the largest factor is `1028263`.

For each of `p - 1`'s factor `f`, we can calculate `e % f = e1^e2^e3 % f = e1^(e2^e3 % phi(f)) % f = e1^(e2^e3 % (f - 1)) % f`.

By applying [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem), we can recover `e`. Then `m = pow(c, inverse(e, p - 1), p)`.

## Flag
`crew{7hi5_1s_4_5ma11er_numb3r_7han_7h3_Gr4ham_numb3r}`

## References
[Euler's totient function](https://en.wikipedia.org/wiki/Euler%27s_totient_function)
[Euler’s theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem)
[Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)
