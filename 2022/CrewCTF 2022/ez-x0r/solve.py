import base64
f = open("flag.enc", "rb")
data = base64.b64decode(f.read())
xor_data = ('f' * len(data)).encode()
flag = (bytes(a ^ b for a, b in zip(data, xor_data))).decode()
assert flag == 'crew{3z_x0r_crypto}'
print(flag)
