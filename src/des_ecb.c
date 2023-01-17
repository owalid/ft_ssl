#include "ft_ssl.h"
#include "libft.h"

unsigned long       encrypt_ecb_block(unsigned long block, unsigned long *iv, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);
    return result;
}

unsigned long       decrypt_ecb_block(unsigned long block, unsigned long *iv, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);
    return result;
}