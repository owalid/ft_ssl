# include "ft_ssl.h"
# include "libft.h"

unsigned long       encrypt_cbc_block(unsigned long block, unsigned long *iv, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block ^ *iv, round_key);

    *iv = result;
    return result;
}

unsigned long       decrypt_cbc_block(unsigned long block, unsigned long *iv, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);

    result ^= *iv;
    *iv = block;
    return result;
}
