#include "ft_ssl.h"

#include <byteswap.h>
#include "ft_ssl.h"
#include <stdio.h>

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		printf("%d", (n >> i) & 1);
	}
	printf(" ");
}

void print_bits(unsigned char *str, size_t len) {
	printf("len: %zu\n", len);
	for (size_t i = 0; i < len; i++) {
		print_bit(str[i]);
	}
	printf("\n");
}


unsigned int K[] = {
    0xd76aa478,
    0xe8c7b756,
    0x242070db,
    0xc1bdceee,
    0xf57c0faf,
    0x4787c62a,
    0xa8304613,
    0xfd469501,
    0x698098d8,
    0x8b44f7af,
    0xffff5bb1,
    0x895cd7be,
    0x6b901122,
    0xfd987193,
    0xa679438e,
    0x49b40821,
    0xf61e2562,
    0xc040b340,
    0x265e5a51,
    0xe9b6c7aa,
    0xd62f105d,
    0x02441453,
    0xd8a1e681,
    0xe7d3fbc8,
    0x21e1cde6,
    0xc33707d6,
    0xf4d50d87,
    0x455a14ed,
    0xa9e3e905,
    0xfcefa3f8,
    0x676f02d9,
    0x8d2a4c8a,
    0xfffa3942,
    0x8771f681,
    0x6d9d6122,
    0xfde5380c,
    0xa4beea44,
    0x4bdecfa9,
    0xf6bb4b60,
    0xbebfbc70,
    0x289b7ec6,
    0xeaa127fa,
    0xd4ef3085,
    0x04881d05,
    0xd9d4d039,
    0xe6db99e5,
    0x1fa27cf8,
    0xc4ac5665,
    0xf4292244,
    0x432aff97,
    0xab9423a7,
    0xfc93a039,
    0x655b59c3,
    0x8f0ccc92,
    0xffeff47d,
    0x85845dd1,
    0x6fa87e4f,
    0xfe2ce6e0,
    0xa3014314,
    0x4e0811a1,
    0xf7537e82,
    0xbd3af235,
    0x2ad7d2bb,
    0xeb86d391
};

unsigned int R[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

int     left_rotate(int n, unsigned int d) {
    return (n << d)|(n >> (32 - d));
}

void    md5_process_firsts_blocks(unsigned int *w, int *vars)
{

    int f, g, a, b, c, d, tmp;

    f = 0;
    g = 0;
    a = vars[0];
    b = vars[1];
    c = vars[2];
    d = vars[3];

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
        b = left_rotate((a + f + K[i] + w[g]), R[i]) + b;
        a = tmp;
    }

    vars[0] += a;
    vars[1] += b;
    vars[2] += c;
    vars[3] += d;
}

void    md5_process_last_block(char *input, int *vars)
{
    size_t len_input = ft_strlen(input);

    print_bits(input, 64);
    input[len_input] = 0x80;
    ft_bzero(input + len_input + 1, 64 - (len_input + 1));
    len_input *= 8;
    ft_memcpy(input + 56, &len_input, 8);
    print_bits(input, 64);
    md5_process_firsts_blocks((unsigned int *) input, vars);
}

void    md5_process(char *input)
{
    int vars[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    int current_len = 64;
    char current_input[64];

    printf("%x%x%x%x\n", vars[0], vars[1], vars[2], vars[3]);
 
    if (ft_strlen(input) >= 64) {
        while (current_len % 64 == 0) {
            ft_strncpy(current_input, input, 64);
            md5_process_firsts_blocks((unsigned int*)current_input, vars);
            input += current_len;
            current_len += ft_strlen(current_input);
        }       
    }

    printf("%d\n", current_len);
    ft_strncpy(current_input, input, 64);
    md5_process_last_block(current_input, vars);
    // unsigned int digest = vars[0] + vars[1] + vars[2] + vars[3];
    printf("%x%x%x%x",__bswap_32(vars[0]), __bswap_32(vars[1]), __bswap_32(vars[2]), __bswap_32(vars[3]));
}