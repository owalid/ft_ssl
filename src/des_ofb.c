# include "ft_ssl.h"
# include "libft.h"

unsigned long       encrypt_ofb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(ssl_mode->iv, round_key);

    ssl_mode->iv = result;
    result ^= block;
    return result;
}

unsigned long       decrypt_ofb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(ssl_mode->iv, round_key);

    ssl_mode->iv = result;
    result ^= block;
    return result;
}
