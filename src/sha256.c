#include "ft_ssl.h"
#include "libft.h"
#include <stdio.h>

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

void    sha256_process_firsts_blocks(void *w, void *vars)
{
    unsigned int * wcopy = (unsigned int*)w;
    unsigned int * vars_cpy = (unsigned int*)vars;
    unsigned int a, b, c, d, e, f, g, h, tmp, ch, maj, t1, t2, s1, s0;
    unsigned int ww[64]; 

    a = vars_cpy[0];
    b = vars_cpy[1];
    c = vars_cpy[2];
    d = vars_cpy[3];
    e = vars_cpy[4];
    f = vars_cpy[5];
    g = vars_cpy[6];
    h = vars_cpy[7];

    for (int i = 0; i < 64; i++) {
        if (i < 16) {
            ww[i] = swap32(wcopy[i]); // convert to big endian
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

    vars_cpy[0] += a;
    vars_cpy[1] += b;
    vars_cpy[2] += c;
    vars_cpy[3] += d;
    vars_cpy[4] += e;
    vars_cpy[5] += f;
    vars_cpy[6] += g;
    vars_cpy[7] += h;
    vars = vars_cpy;
}


// void    sha256_process_last_block(char *input, unsigned int *vars)
// {
//     size_t len_input = ft_strlen(input);

//     input[len_input] = 0x80;
//     ft_bzero(input + len_input + 1, 64 - (len_input + 1));
//     len_input *= 8;
//     len_input = swap64(len_input);
//     ft_memcpy(input + 56, &len_input, 8);
//     sha256_process_firsts_blocks((unsigned int*)input, vars);
// }


void    sha256_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type)
{
    unsigned int vars[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    fn_process(input, input_type, 64, vars, 1, sha256_process_firsts_blocks);
    printf("\n%08x%08x%08x%08x%08x%08x%08x%08x \n",vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7]);
    // int current_len = 64;
    // char current_input[64];

    // if (ft_strlen(input) >= 64) {
    //     while (current_len % 64 == 0) {
    //         ft_strncpy(current_input, input, 64);
    //         sha256_process_firsts_blocks((unsigned int*)current_input, vars);
    //         input += current_len;
    //         current_len += ft_strlen(current_input);
    //     }       
    // }

    // ft_strncpy(current_input, input, 64);
    // sha256_process_last_block(current_input, vars);
    // printf("\n%08x%08x%08x%08x%08x%08x%08x%08x \n",vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6], vars[7]);
}