# include "ft_ssl.h"
# include "libft.h"

unsigned long       encrypt_cbc_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block ^  ssl_mode->iv, round_key);

    ssl_mode->iv = result;
    return result;
}

unsigned long       decrypt_cbc_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(block, round_key);

    result ^=  ssl_mode->iv;
     ssl_mode->iv = block;
    return result;
}
