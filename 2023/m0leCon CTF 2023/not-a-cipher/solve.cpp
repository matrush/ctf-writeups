#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <cassert>

#include "defs.h"

using namespace std;

#define u64 unsigned long long
#define u32 unsigned int
#define u16 unsigned short
#define i16 short
#define u8 unsigned char
#define i8 char

const string plaintext = "[ehy watch d1z](https://www.youtube.com/watch?v=FH9yt8qTACw)";
const string ciphertext_encoded = "59b9587b995a03c653fa9849a2746dbaba5fd6ad58089c04e472474d7442f7cd5840bc03e1bf462dce4a876c452dab0dd4fc144bcb13b38b6c91c404";
const string cipherflag_encoded = "52ac5d29d00075e1586dbe5e437274bb67475c7c594db704415a5aabd15cfdd303bdaa5f82d103bca7";

class EncodingMachine
{
    u8 buffer = 0;
    i8 dc_offset = 0;
    int cnt = 0;
    vector<char> pool;

    char *encode_buffer(char *buf)
    {
        switch (buffer)
        {
        case 0u:
            if (dc_offset >= 0)
            {
                dc_offset -= 1;
                *buf = '0';
                buf[1] = '-';
                buf[2] = '0';
            }
            else
            {
                dc_offset += 2;
                *buf = '+';
                buf[1] = '0';
                buf[2] = '+';
            }
            break;
        case 1u:
            *buf = '0';
            buf[1] = '-';
            buf[2] = '+';
            break;
        case 2u:
            *buf = '+';
            buf[1] = '-';
            buf[2] = '0';
            break;
        case 3u:
            if (dc_offset < 2)
            {
                dc_offset += 1;
                *buf = '0';
                buf[1] = '0';
                buf[2] = '+';
            }
            else
            {
                dc_offset -= 2;
                *buf = '-';
                buf[1] = '-';
                buf[2] = '0';
            }
            break;
        case 4u:
            *buf = '-';
            buf[1] = '+';
            buf[2] = '0';
            break;
        case 5u:
            if (dc_offset == -1)
            {
                dc_offset += 2;
                *buf = '0';
                buf[1] = '+';
                buf[2] = '+';
            }
            else
            {
                dc_offset -= 1;
                *buf = '-';
                buf[1] = '0';
                buf[2] = '0';
            }
            break;
        case 6u:
            if (dc_offset <= 0)
            {
                dc_offset += 1;
                *buf = '-';
                buf[1] = '+';
                buf[2] = '+';
            }
            else
            {
                dc_offset -= 1;
                *buf = '-';
                buf[1] = '-';
                buf[2] = '+';
            }
            break;
        case 7u:
            *buf = '-';
            buf[1] = '0';
            buf[2] = '+';
            break;
        case 8u:
            if (dc_offset == 2)
            {
                dc_offset -= 2;
                *buf = '0';
                buf[1] = '-';
                buf[2] = '-';
            }
            else
            {
                dc_offset += 1;
                *buf = '+';
                buf[1] = '0';
                buf[2] = '0';
            }
            break;
        case 9u:
            if (dc_offset == 2)
            {
                dc_offset -= 3;
                *buf = '-';
                buf[1] = '-';
                buf[2] = '-';
            }
            else
            {
                dc_offset += 1;
                *buf = '+';
                buf[1] = '-';
                buf[2] = '+';
            }
            break;
        case 0xAu:
            if (dc_offset >= 1)
            {
                dc_offset -= 1;
                *buf = '+';
                buf[1] = '-';
                buf[2] = '-';
            }
            else
            {
                dc_offset += 1;
                *buf = '+';
                buf[1] = '+';
                buf[2] = '-';
            }
            break;
        case 0xBu:
            *buf = '+';
            buf[1] = '0';
            buf[2] = '-';
            break;
        case 0xCu:
            if (dc_offset == -1)
            {
                dc_offset += 3;
                *buf = '+';
                buf[1] = '+';
                buf[2] = '+';
            }
            else
            {
                dc_offset -= 1;
                *buf = '-';
                buf[1] = '+';
                buf[2] = '-';
            }
            break;
        case 0xDu:
            if (dc_offset < 2)
            {
                dc_offset += 1;
                *buf = '0';
                buf[1] = '+';
                buf[2] = '0';
            }
            else
            {
                dc_offset -= 2;
                *buf = '-';
                buf[1] = '0';
                buf[2] = '-';
            }
            break;
        case 0xEu:
            *buf = '0';
            buf[1] = '+';
            buf[2] = '-';
            break;
        case 0xFu:
            if (dc_offset >= 0)
            {
                dc_offset -= 1;
                *buf = '0';
                buf[1] = '0';
                buf[2] = '-';
            }
            else
            {
                dc_offset += 2;
                *buf = '+';
                buf[1] = '+';
                buf[2] = '0';
            }
            break;
        default:
            *buf = 'x';
            buf[1] = 'x';
            buf[2] = 'x';
            break;
        }
        return buf;
    }

public:
    void
    inject(u8 bit)
    {
        buffer = (buffer << 1) | bit;
        cnt += 1;
        if (cnt == 4)
        {
            char buf[3];
            encode_buffer(buf);
            pool.insert(pool.begin(), buf[2]);
            pool.insert(pool.begin(), buf[1]);
            pool.insert(pool.begin(), buf[0]);
            cnt = 0;
            buffer = 0;
        }
    }

    char extract()
    {
        if (pool.empty())
        {
            return 'x';
        }
        else
        {
            char c = pool.back();
            pool.pop_back();
            return c;
        }
    }
};

class Cipher
{
    u64 lfsr = 0;
    EncodingMachine encoder;

public:
    Cipher(u64 k, u32 nonce)
    {
        lfsr = (((WORD2(k) | 0xDEADBEEF0000LL) << 32) & 0xFFFFFFFFFFFFLL | (unsigned int)k) ^ nonce;
        // cout << "lfsr: " << lfsr << endl;
        encoder = EncodingMachine();
    }

    vector<u8> get_keystream(int byte_len)
    {
        vector<u8> result;
        do
        {
            u16 v7 = 0;
            u8 v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            u8 v11 = encoder.extract();
            v7 = v11 | (unsigned __int16)(v7 << 8);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            v8 = get_keystream_bit();
            v7 = v8 | (unsigned __int16)(2 * v7);
            result.push_back(HIBYTE(v7));
            result.push_back(LOBYTE(v7));
            v7 = 0;
            u8 value = encoder.extract();
            result.push_back(value);
        } while (result.size() < byte_len);
        return result;
    }

    u8 get_keystream_bit()
    {
        bool v22 = (lfsr & 0x100000000000LL) != 0;
        bool v20 = (lfsr & 0x40000000000LL) != 0;
        bool v31 = (lfsr & 0x200000000000LL) != 0;
        bool v34 = (lfsr & 0x20000000000LL) != 0;
        u8 v35 = v34 ^ (2 * v20) ^ (4 * v22) ^ (8 * v31);
        u8 v30[16];
        v30[0] = 1;
        v30[1] = 0;
        v30[2] = 0;
        v30[3] = 0;
        v30[4] = 1;
        v30[5] = 0;
        v30[6] = 0;
        v30[7] = 1;
        v30[8] = 1;
        v30[9] = 1;
        v30[10] = 0;
        v30[11] = 1;
        v30[12] = 1;
        v30[13] = 0;
        v30[14] = 1;
        v30[15] = 0;
        u8 v19 = v30[v35];
        bool v18 = (lfsr & 0x800000000LL) != 0;
        bool v16 = (lfsr & 0x200000000LL) != 0;
        bool v49 = (lfsr & 0x8000000000LL) != 0;
        bool v52 = BYTE4(lfsr) & 1;
        u8 v53 = BYTE4(lfsr) & 1 ^ (2 * v16) ^ (4 * v18) ^ (8 * v49);
        char v48[16];
        v48[0] = 1;
        v48[1] = 0;
        v48[2] = 0;
        v48[3] = 0;
        v48[4] = 0;
        v48[5] = 0;
        v48[6] = 0;
        v48[7] = 1;
        v48[8] = 1;
        v48[9] = 1;
        v48[10] = 1;
        v48[11] = 0;
        v48[12] = 0;
        v48[13] = 1;
        v48[14] = 1;
        v48[15] = 1;
        u8 v15 = v48[v53];
        bool v14 = (lfsr & 0x4000000) != 0;
        bool v12 = BYTE3(lfsr) & 1;
        bool v43 = (lfsr & 0x40000000) != 0;
        bool v46 = (lfsr & 0x200000) != 0;
        u8 v47 = v46 ^ (2 * v12) ^ (4 * v14) ^ (8 * v43);
        char v42[16];
        v42[0] = 1;
        v42[1] = 0;
        v42[2] = 0;
        v42[3] = 0;
        v42[4] = 0;
        v42[5] = 0;
        v42[6] = 0;
        v42[7] = 1;
        v42[8] = 1;
        v42[9] = 1;
        v42[10] = 1;
        v42[11] = 0;
        v42[12] = 0;
        v42[13] = 1;
        v42[14] = 1;
        v42[15] = 1;
        u8 v11 = v42[v47];
        bool v10 = (lfsr & 0x40000) != 0;
        bool v8 = WORD1(lfsr) & 1;
        bool v37 = (lfsr & 0x80000) != 0;
        bool v40 = (lfsr & 0x4000) != 0;
        u8 v41 = v40 ^ (2 * v8) ^ (4 * v10) ^ (8 * v37);
        char v36[16];
        v36[0] = 1;
        v36[1] = 0;
        v36[2] = 0;
        v36[3] = 0;
        v36[4] = 0;
        v36[5] = 0;
        v36[6] = 0;
        v36[7] = 1;
        v36[8] = 1;
        v36[9] = 1;
        v36[10] = 1;
        v36[11] = 0;
        v36[12] = 0;
        v36[13] = 1;
        v36[14] = 1;
        v36[15] = 1;
        u8 v7 = v36[v41];
        bool v6 = (lfsr & 0x10) != 0;
        bool v4 = (lfsr & 8) != 0;
        bool v25 = (lfsr & 0x2000) != 0;
        bool v28 = (lfsr & 2) != 0;
        u8 v29 = v28 ^ (2 * v4) ^ (4 * v6) ^ (8 * v25);
        char v24[16];
        v24[0] = 1;
        v24[1] = 0;
        v24[2] = 0;
        v24[3] = 0;
        v24[4] = 1;
        v24[5] = 0;
        v24[6] = 0;
        v24[7] = 1;
        v24[8] = 1;
        v24[9] = 1;
        v24[10] = 0;
        v24[11] = 1;
        v24[12] = 1;
        v24[13] = 0;
        v24[14] = 1;
        v24[15] = 0;
        u8 v1 = v24[v29];
        u8 v54[37];
        v54[32] = v19;
        v54[33] = v15;
        v54[34] = v11;
        v54[35] = v7;
        v54[36] = v1;
        u8 v55 = v1 ^ (2 * v7) ^ (4 * v11) ^ (8 * v15) ^ (16 * v19);
        v54[0] = 0;
        v54[1] = 1;
        v54[2] = 0;
        v54[3] = 1;
        v54[4] = 1;
        v54[5] = 0;
        v54[6] = 1;
        v54[7] = 1;
        v54[8] = 1;
        v54[9] = 0;
        v54[10] = 0;
        v54[11] = 1;
        v54[12] = 1;
        v54[13] = 1;
        v54[14] = 0;
        v54[15] = 0;
        v54[16] = 1;
        v54[17] = 0;
        v54[18] = 1;
        v54[19] = 0;
        v54[20] = 1;
        v54[21] = 0;
        v54[22] = 1;
        v54[23] = 0;
        v54[24] = 1;
        v54[25] = 1;
        v54[26] = 0;
        v54[27] = 0;
        v54[28] = 1;
        v54[29] = 0;
        v54[30] = 0;
        v54[31] = 0;
        u8 v3 = v54[v55];
        u8 v23 =
            lfsr & 1 ^
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
        encoder.inject((lfsr & 0x40) != 0);
        lfsr *= 2LL;
        lfsr &= 0xFFFFFFFFFFFFuLL;
        lfsr |= v23;
        return v3;
    }
};

static string decode(const string &str)
{
    string result = "";
    for (int i = 0; i < str.length(); i += 2)
    {
        u8 v = stoi(str.substr(i, 2), 0, 16);
        result += char(v);
    }
    return result;
}

static string xor_str(const string &s1, const string &s2)
{
    string result = "";
    for (int i = 0; i < min(s1.length(), s2.length()); i++)
    {
        u8 v = s1[i] ^ s2[i];
        result += char(v);
    }
    return result;
}

static vector<u8> xor_vec(const vector<u8> &s1, const vector<u8> &s2)
{
    vector<u8> result;
    for (int i = 0; i < min(s1.size(), s2.size()); i++)
    {
        u8 v = s1[i] ^ s2[i];
        result.push_back(v);
    }
    return result;
}

static vector<u8> to_vec(string s)
{
    vector<u8> result;
    for (int i = 0; i < s.length(); ++i)
    {
        result.push_back((u8)s[i]);
    }
    return result;
}

static string to_str(vector<u8> &vec) {
    string s;
    for (int i = 0; i < vec.size(); ++i) {
        s += char(vec[i]);
    }
    return s;
}

static void print(vector<u8> &vec)
{
    for (int i = 0; i < vec.size(); ++i)
    {
        if (i)
        {
            cout << ' ';
        }
        cout << (int)vec[i];
    }
    cout << endl;
}

Cipher c(0, 0);
vector<u8> rand_str_vec;

int main()
{
    string ciphertext = decode(ciphertext_encoded);
    string target_rand_str = xor_str(plaintext, ciphertext);
    vector<u8> target_rand_vec = to_vec(target_rand_str);
    // k is from solve.py
    const u64 k = 0x55d44aa7c2c0;
    const u32 nonce1 = 909929503;
    c = Cipher(k, nonce1);
    rand_str_vec = c.get_keystream(target_rand_vec.size());
    assert(std::equal(target_rand_vec.begin(), target_rand_vec.end(), rand_str_vec.begin()));

    const u32 nonce2 = 1540254874;
    c = Cipher(k, nonce2);
    const string cipherflag = decode(cipherflag_encoded);
    vector<u8> cipherflag_vec = to_vec(cipherflag);
    rand_str_vec = c.get_keystream(cipherflag_vec.size());
    vector<u8> xored_vec = xor_vec(rand_str_vec, cipherflag_vec);
    string flag = to_str(xored_vec);
    assert(flag == "ptm{n0w_u_kn0w_how_ur_c4r_will_b3_st0l3n}");
    cout << flag << endl;
    // ptm{n0w_u_kn0w_how_ur_c4r_will_b3_st0l3n}
}
