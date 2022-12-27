#include "ft_ssl.h"
#include "libft.h"

unsigned int H_BLAKE2B[] = {
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179
};

unsigned int SIGMA[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
};


unsigned int mix(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned y) {
    a += b + x;
    d = right_rotate_64((d ^ a), 32);

    c += d;
    b = right_rotate_64((b ^ c), 24);

    a += b + y;
    d = right_rotate_64((d ^ a), 16);

    c += d;
    b = right_rotate_64(b ^ c, 63);
}

unsigned int compress(unsigned int h, unsigned long chunk, int t, int is_last)
{
    for (int i = 0; i < 12; i++) {
        mix(v[0], v[4], v[8], v[12], m[S0], m[S1]);
        mix(v[1], v[5], v[9], v[13], m[S2], m[S3]);
        mix(v[2], v[6], v[10], v[14], m[S4], m[S5]);
        mix(v[3], v[7], v[11], v[15], m[S6], m[S7]);

        mix(v[0], v[5], v[10], v[15], m[S8], m[S9]);
        mix(v[1], v[6], v[11], v[12], m[S10], m[S11]);
        mix(v[2], v[7], v[8], v[13], m[S12], m[S13]);
        mix(v[3], v[4], v[9], v[14], m[S14], m[S15]);
    }
}



void   blake2s256_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    unsigned int vars[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

    int res = fn_process(input, input_type, 64, vars, 0, md5_process_firsts_blocks);
    if (res == 1) {
        for (int i = 0; i < 4; i++)
            vars[i] = swap32(vars[i]);

        preprocess_final_output(ssl_mode, algo_name, input_type, input, print_hash_32, vars, 4);
    }
}