# include "ft_ssl.h"
# include "libft.h"

ssize_t     unpad(unsigned char *plain_block)
{
    ssize_t result = 6;
    char last_char = plain_block[7];
    plain_block[7] = 0;

    for (;result >= 0; result--)
    {
        if (last_char != plain_block[result])
            return result + 1;
        else
            plain_block[result] = 0;
    }
    return result + 1;
}

void        pad_block(unsigned char *input, ssize_t len_input)
{
    int diff = 8 - len_input;
    int i = len_input % 8;
    for (; i < 8; i++)
        input[i] = diff;
}

void        display_key(unsigned long *r_k)
{
    for (int i=0; i < 16; i++)
        printf("r_k[%d]\t= %lu\n", i, r_k[i]);
}

void        print_cipher_b64(unsigned long* blocks, int* len_block, int fd)
{
    // printf("len_block: %d", *len_block);
    // 8 char in an unsigned long (8*8)
    three_bytes_to_b64((char *)blocks, (*len_block)*8, 1, fd);
    ft_bzero(blocks, 3*8);
    *len_block = 0;
}


void    print_cipher_raw(unsigned long* blocks, int *len_block, int fd, int len_last)
{
    if (len_last == 0)
        len_last = 8;
    // printf("len_last: %d\n", len_last);
    int i = 0;

    for (; i < *len_block - 1; i++)
        write(fd, &blocks[i], 8);

    // printf("i: %d", i);
    // printf("blocks[i]: %lu", blocks[i+1]);

    write(fd, &blocks[i], len_last);

    ft_bzero(blocks, 3*8);
    *len_block = 0;
}

void        reverse_round_key(unsigned long *r_k)
{
    // use in description
    unsigned long tmp_r_k[16];
    ft_bzero(tmp_r_k, 16*8);

    for (int i = 0; i < 16; i++)
        tmp_r_k[i] = r_k[i];
    for (int i = 15, j = 0; j < 16; i--, j++)
        r_k[i] = tmp_r_k[j];
}