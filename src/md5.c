#include "ft_ssl.h"
#include "libft.h"
#include <byteswap.h>
#include <stdio.h>
#include <fcntl.h>

unsigned int K_md5[] = {
    0xd76aa478,	0xe8c7b756,	0x242070db,	0xc1bdceee,	0xf57c0faf,	0x4787c62a,	0xa8304613,	0xfd469501,
    0x698098d8,	0x8b44f7af,	0xffff5bb1,	0x895cd7be,	0x6b901122,	0xfd987193,	0xa679438e,	0x49b40821,
    0xf61e2562,	0xc040b340,	0x265e5a51,	0xe9b6c7aa,	0xd62f105d,	0x02441453,	0xd8a1e681,	0xe7d3fbc8,
    0x21e1cde6,	0xc33707d6,	0xf4d50d87,	0x455a14ed,	0xa9e3e905,	0xfcefa3f8,	0x676f02d9,	0x8d2a4c8a,
    0xfffa3942,	0x8771f681,	0x6d9d6122,	0xfde5380c,	0xa4beea44,	0x4bdecfa9,	0xf6bb4b60,	0xbebfbc70,
    0x289b7ec6,	0xeaa127fa,	0xd4ef3085,	0x04881d05,	0xd9d4d039,	0xe6db99e5,	0x1fa27cf8,	0xc4ac5665,
    0xf4292244,	0x432aff97,	0xab9423a7,	0xfc93a039,	0x655b59c3,	0x8f0ccc92,	0xffeff47d,	0x85845dd1,
	0x6fa87e4f,	0xfe2ce6e0,	0xa3014314,	0x4e0811a1,	0xf7537e82,	0xbd3af235,	0x2ad7d2bb,	0xeb86d391
};

unsigned int R[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

void    md5_process_firsts_blocks(void *w, void *vars)
{
    unsigned int * ww = (unsigned int*)w;
    unsigned int * vars_cpy = (unsigned int*)vars;
    unsigned int f, g, a, b, c, d, tmp;

    f = 0;
    g = 0;
    a = vars_cpy[0];
    b = vars_cpy[1];
    c = vars_cpy[2];
    d = vars_cpy[3];

    for (int i = 0; i < 64; i++) {
        if (i <= 15) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i >= 16 && i <= 31) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i >= 32 && i <= 47) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else if (i >= 48) {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }

        tmp = d;
        d = c;
        c = b;
        b = left_rotate((a + f + K_md5[i] + ww[g]), R[i]) + b;
        a = tmp;
    }

    vars_cpy[0] += a;
    vars_cpy[1] += b;
    vars_cpy[2] += c;
    vars_cpy[3] += d;
    vars = vars_cpy;
}

void   md5_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type)
{
    unsigned int vars[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };

    fn_process(input, input_type, 64, vars, 0, md5_process_firsts_blocks);
    for (int i = 0; i < 4; i++)
    {
        vars[i] = swap32(vars[i]);
    }
    print_hash_32(vars, 4);
}