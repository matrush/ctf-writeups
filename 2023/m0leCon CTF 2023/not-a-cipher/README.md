# not-a-cipher

## Challenge [[Link]](https://ctftime.org/event/2033)
> I tried to encrypt the flag with my car key... Sorry what?
>
> Author: @Rising

## Solution
First of all, this is a reversing + crypto challenge. From IDA Pro analysis it's not hard to figure out this is a Rust reverseing challenge. We will leverage the [IDA Pro Rust analysis plugin](https://hex-rays.com/blog/rust-analysis-plugin-tech-preview/) here.

This is the decompiled pseudocode of the `main` function:
```c
  urandom::new::h22209ac9f00a6ed0(&rnd_eng);
  k = urandom::random::Random$LT$R$GT$::next::hfe9849b815fb3319(&rnd_eng) & 0xFFFFFFFFFFFFLL;
  random_nonce = urandom::random::Random$LT$R$GT$::next::he04b5e4ab7523e56(&rnd_eng);
  not_a_cipher::cipher::Cipher::new::hcb092554f3db13f6(&cipher, k, random_nonce);
  byte_len = alloc::vec::Vec$LT$T$C$A$GT$::len::h1274882a8a2810df(&plaintext);
  not_a_cipher::cipher::Cipher::get_keystream::ha011a87789b68fe5(&rand_str, &cipher, byte_len);
  while ( rand_str[i] )
  {
    alloc::vec::Vec$LT$T$C$A$GT$::push::hce92b16b409d07d4(&xored_str, rand_str[i] ^ plaintext[i]);
    ++i;
  }
```

This is the `output.txt`:
```
nonce: 909929503
ciphertext: 59b9587b995a03c653fa9849a2746dbaba5fd6ad58089c04e472474d7442f7cd5840bc03e1bf462dce4a876c452dab0dd4fc144bcb13b38b6c91c404
--- and now the flag! ---
nonce: 1540254874
flag: 52ac5d29d00075e1586dbe5e437274bb67475c7c594db704415a5aabd15cfdd303bdaa5f82d103bca7
```

Comparing the above logic with what we have in `output.txt`, we can see that the `random_nonce` and the `xored_str` are known. The `k` is unknown. The `Cipher` class takes a `k` and `nonce` to initialize itself, and then was able to generate `n` bits with the `Cipher::get_keystream` function. So if we reverse the `xor` operation, the task is now to find the `k` so that the given random bits can be generated from the PRNG. Once we have the `k`, combining it with the second `nonce`, we can generate the random bits that used to xor the original flag, then we can get the final flag.

The PRNG is a little bit tricky. In function ` not_a_cipher::cipher::Cipher::new::hcb092554f3db13f6` at `0xA400`, we can see the following logic:
```c
cipher->lfsr = (((WORD2(k) | 0xDEADBEEF0000LL) << 32) & 0xFFFFFFFFFFFFLL | (unsigned int)k) ^ nonce;
cipher->encoder = not_a_cipher::encoding_machine::EncodingMachine::new::hd87d50757abc4418(&machine);
```
Simplify it a bit, the `lfsr = k ^ nonce`, where `k` is 48 bits long.

Then in function `not_a_cipher::cipher::Cipher::get_keystream::ha011a87789b68fe5` at `0xBFD0`, we can see the following logic:
```c
do {
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v11 = not_a_cipher::encoding_machine::EncodingMachine::extract::h18d3df3649b13e97(&self->encoder);
    v7 = v11 | (unsigned __int16)(v7 << 8);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    v8 = not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543(self);
    v7 = v8 | (unsigned __int16)(2 * v7);
    alloc::vec::Vec$LT$T$C$A$GT$::push::hce92b16b409d07d4(&v6, HIBYTE(v7));
    alloc::vec::Vec$LT$T$C$A$GT$::push::hce92b16b409d07d4(&v6, v7);
    v7 = 0;
    value = not_a_cipher::encoding_machine::EncodingMachine::extract::h18d3df3649b13e97(&self->encoder);
    alloc::vec::Vec$LT$T$C$A$GT$::push::hce92b16b409d07d4(&v6, value);
} while ( alloc::vec::Vec$LT$T$C$A$GT$::len::h1274882a8a2810df(&v6) < byte_len );
```

We can see that the random string is a stream of two bytes of a short integer, followed by a char extracted from a pool of the encoding machine. Notice that the first extracted char `v11` is actually hidden inside of `v7`, which is the 4th-11th rightmost bits of the final `v7`. The encode logic `not_a_cipher::encoding_machine::EncodingMachine::encode_buffer::h12f585480f01e78d` at `0xF810` is mapping 4 bits to 3 chars consists of `+`, `-` and `0`. The reverse mapping is like this:
```python
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
```

In `not_a_cipher::cipher::Cipher::keystream_bit::h77fab4d4b56ec543` at `0xA510`, we can see this is the main logic of the Linear Feedback Shift Register. The logic looks like this:
```c
not_a_cipher::encoding_machine::EncodingMachine::inject::h4b0d549a9d46722e(&self->encoder, (self->lfsr & 0x40) != 0);
self->lfsr *= 2LL;
self->lfsr &= 0xFFFFFFFFFFFFuLL;
self->lfsr |= lfsr & 1 ^
    ((lfsr & 0x2) != 0) ^
    ((lfsr & 0x10) != 0) ^
    ((lfsr & 0x20) != 0) ^
    ((lfsr & 0x40) != 0) ^
    ((lfsr & 0x20000) != 0) ^
    ((lfsr & 0x200000) != 0) ^
    ((lfsr & 0x1000000) != 0) ^
    ((lfsr & 0x2000000) != 0) ^
    ((lfsr & 0x80000000) != 0) ^
    ((lfsr & 0x8000000000LL) != 0) ^
    ((lfsr & 0x10000000000LL) != 0) ^
    ((lfsr & 0x20000000000LL) != 0) ^
    ((lfsr & 0x100000000000LL) != 0) ^
    ((lfsr & 0x200000000000LL) != 0) ^
    ((lfsr & 0x800000000000LL) != 0);
return result;
```

After some research, we find it's actually the [Hitag2 stream cipher](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final95.pdf). The cipher consists of a 48-bit linear feedback shift register (LFSR) and a non-linear filter function `f`. For each clock tick, twenty bits of the LFSR are put through the filter function, generating one bit of keystream. Then the LFSR shifts one bit to the left, using the generating polynomial to generate a new bit on
the right.

The feedback function L is defined by `L(x0 ...x47) := x0 ⊕ x2 ⊕ x3 ⊕ x6 ⊕ x7 ⊕ x8 ⊕ x16 ⊕ x22 ⊕ x23 ⊕ x26 ⊕ x30 ⊕ x41 ⊕ x42 ⊕ x43 ⊕ x46 ⊕ x47.` The filter function used for generating the random bit doesn't do much here so we will skip.

So for each new bit we generated, the 6th right-most bit of the latest `lfsr` is being pushed to the 4 bits buffer to get the mapped `+-0` stream.

Now we have all the information. From the xored output we can get the full `+-0` stream, then we can use the mapping to get the full binary stream `bs`, with each bit being the 6th right most bit of the latest `lfsr`. So the first 7 bits of `bs` are the last 7 bits of the initial `lfsr`. The remaining problem is how can we get the first `48 - 7` bits of the initial `lfsr`. Remember that we have many unused bits from `bs` after the first 7 bits. For each bit of `bs`, it's actually generated using the `L` feedback function. Thus we have the rollback function R defined by `R(x1 ... x48) := x2 ⊕ x3 ⊕ x6 ⊕ x7 ⊕ x8 ⊕ x16 ⊕ x22 ⊕ x23 ⊕ x26 ⊕ x30 ⊕ x41 ⊕ x42 ⊕ x43 ⊕ x46 ⊕ x47 ⊕ x48.` If one first shifts the LFSR left using L to generate a new bit on the right, then R recovers the bit that dropped out on the left, i.e., `x0 = R(x1 ...x47 L(x0 ...x47))`. So we can simply using this equation to recover each bits of the remaining `48 - 7` bits one by one from the rightmost bit.

Once we recovered all the bits, we get the initial `lfsr = 0x55d47c9baedf`, and then `k = lfsr ^ nonce = 0x55d47c9baedf ^ 909929503 = 0x55d44aa7c2c0`. Then we can either reconstruct the Cipher using script or override the `k` during runtime to get the 41 random bits to xor with the encrypted flag.

The attached `solve.py` recovers the `+-0` stream and then recovers binary stream `bs`, then recovers the full 48 bits of the `lfsr` using the rollback mechanism and outputs the `k`. The `solve.cpp` reconstructed the Cipher and EncodingMachine using C++, and used the given `k` and `nonce` to generate the 41 bits and recover the flag.

## Flag
`ptm{y0u_found_another_w4y_t0_factorize}`