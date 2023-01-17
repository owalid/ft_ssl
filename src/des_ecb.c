#include "ft_ssl.h"
#include "libft.h"

unsigned long       encrypt_ecb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);
    return result;
}

unsigned long       decrypt_ecb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);
    return result;
}