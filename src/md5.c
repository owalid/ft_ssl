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

void    md5_process_firsts_blocks(unsigned int *w, unsigned int *vars)
{

    unsigned int f, g, a, b, c, d, tmp;

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
        b = left_rotate((a + f + K_md5[i] + w[g]), R[i]) + b;
        a = tmp;
    }

    vars[0] += a;
    vars[1] += b;
    vars[2] += c;
    vars[3] += d;
}


void    md5_process_last_block(char *input, unsigned int *vars, size_t readed)
{
    size_t len_input = (readed == -1) ? ft_strlen(input) : readed;

    ft_bzero(input + len_input + 1, 64 - (len_input + 1));
    input[len_input] = 0x80;

    if (len_input >= 56) {
        char tmp_input[64];

        ft_bzero(tmp_input, 64);
        len_input *= 8;
        ft_memcpy(tmp_input + 56, &len_input, 8);
        md5_process_firsts_blocks((unsigned int*)input, vars);
        md5_process_firsts_blocks((unsigned int*)tmp_input, vars);
    } else {
        len_input *= 8;
        ft_memcpy(input + 56, &len_input, 8);
        md5_process_firsts_blocks((unsigned int*)input, vars);
    }
}

void   md5_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type)
{
    unsigned int vars[] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    char current_input[64];

    if (input_type == 0) {
        int current_len = 64;

        if (ft_strlen(input) >= 64) {
            while (current_len % 64 == 0) {
                ft_strncpy(current_input, input, 64);
                md5_process_firsts_blocks((unsigned int*)current_input, vars);
                input += current_len;
                current_len += ft_strlen(current_input);
            }       
        }

        ft_strncpy(current_input, input, 64);
        md5_process_last_block(current_input, vars, -1);
        printf("%08x%08x%08x%08x\n",__bswap_32(vars[0]), __bswap_32(vars[1]), __bswap_32(vars[2]), __bswap_32(vars[3]));
    } else if (input_type == 1 || input_type == 2) {
        printf("not ready yet \n");
        printf("input_type: %d\n", input_type);
        int fd = (input_type == 2) ? 0 : open(input, O_RDONLY);

        // TODO REMOVE DEBUG
        if (fd == 0) {
            printf("stdin\n");
        } else if (fd > 1) {
            printf("file process %s: fd:%d\n", input, input_type);
        } else {
            printf("file not exist\n");
        }
        // END DEBUG

        if (fd > -1) {
            int readed = read(fd, current_input, 64);
            printf("readed: %d", readed);
            while (readed) {
                if (readed < 64) {
                    md5_process_last_block(current_input, vars, readed);
                    printf("%08x%08x%08x%08x\n",__bswap_32(vars[0]), __bswap_32(vars[1]), __bswap_32(vars[2]), __bswap_32(vars[3]));
                    break;
                } else {
                    md5_process_firsts_blocks((unsigned int*)current_input, vars);
                    readed = read(fd, current_input, 64);
                }
            }
        }
    }
}