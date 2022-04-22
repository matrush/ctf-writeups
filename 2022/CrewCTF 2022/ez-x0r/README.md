# ez-x0r

## Challenge [[Link]](https://ctftime.org/task/20367)
> its simple xor

## Solution

The given `flag.enc` file is a text file with the string `BRQDER1VHDkeVhQ5BRQfFhIJGw==`. One can easily tell it's a `base64` encoded string because of the `==` at the end.

Decoding it via ```cat flag.enc | base64 -d``` returns an unreadable string. Since the flag format is `crew{xxx}` and the challenge statement says it's simple xor, we can try `xor` them.

After `xor`, we can find the key is `fffff......`. Then we just need to xor the decoded string with all `f`s and get the final flag.

```python
import base64
f = open("flag.enc", "rb")
data = base64.b64decode(f.read())
xor_data = ('f' * len(data)).encode()
flag = (bytes(a ^ b for a, b in zip(data, xor_data))).decode()
assert flag == 'crew{3z_x0r_crypto}'
print(flag)
```

## Flag
`crew{3z_x0r_crypto}`
