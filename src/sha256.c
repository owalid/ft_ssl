#include "ft_ssl.h"
#include "libft.h"

unsigned int K_SHA256[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void    sha256_process_firsts_blocks(void *raw_w, void *raw_hash)
{
    unsigned int * w = (unsigned int*)raw_w;
    unsigned int * hash = (unsigned int*)raw_hash;
    unsigned int a, b, c, d, e, f, g, h, ch, maj, t1, t2, s1, s0;
    unsigned int ww[64]; 

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        if (i < 16) {
            ww[i] = swap32(w[i]); // convert to big endian
        } else {
            s0 = right_rotate_32(ww[i-15], 7) ^ right_rotate_32(ww[i-15], 18) ^ ww[i-15] >> 3;
            s1 = right_rotate_32(ww[i-2], 17) ^ right_rotate_32(ww[i-2], 19) ^ ww[i-2] >> 10;
            ww[i] = ww[i-16] + s0 + ww[i-7] + s1;               
        }
    }

    for (int i = 0; i < 64; i++) {
        s1 = right_rotate_32(e, 6) ^ right_rotate_32(e, 11) ^ right_rotate_32(e, 25);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + s1 + ch + K_SHA256[i] + ww[i];

        s0 = right_rotate_32(a, 2) ^ right_rotate_32(a, 13) ^ right_rotate_32(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
    raw_hash = hash;
}


void    sha256_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    unsigned int vars[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


    int res = fn_process(input, input_type, 64, vars, 1, sha256_process_firsts_blocks, ssl_mode, algo_name);

    if (res == 1)
        preprocess_final_output(ssl_mode, algo_name, input_type, input, print_hash_32, vars, 8);
}


unsigned long simple_sha256(char *input)
{
    // , char *hash_str
    unsigned int vars_int[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    unsigned long res = 0;
    char hash_str[65];
    ft_bzero(hash_str, 65);

    fn_process(input, 0, 64, vars_int, 1, sha256_process_firsts_blocks, NULL, NULL);
    char *str;

    for (int i = 0; i < 8; i++)
    {
        str = ft_utoa_base(vars_int[i], 16);
        ft_memcpy(hash_str + i * 8, str, 8);
        free(str);
    }

    res = ft_hextol(hash_str);
    return res;
}

// unsigned long hmac_sha256(char *input, unsigned long key)
// {

// }

// 6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19