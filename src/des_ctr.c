# include "ft_ssl.h"
# include "libft.h"

unsigned long       encrypt_ctr_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(ssl_mode->iv ^ ssl_mode->counter, round_key);

    result ^= block;
    ssl_mode->counter++;
    return result;
}

unsigned long       decrypt_ctr_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key)
{
    unsigned long result = encrypt_block(ssl_mode->iv ^ ssl_mode->counter, round_key);
    
    result ^= block;
    ssl_mode->counter++;
    return result;
}
