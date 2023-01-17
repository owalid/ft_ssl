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

void        des_cbc_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    unsigned long r_k[16];

    ft_bzero(r_k, 16*8);

    // process round key
    process_round_keys(ssl_mode->key, r_k);

    if (ssl_mode->decode_mode == 1) des_decrypt(ssl_mode, r_k, 1, decrypt_cbc_block);
    else des_encrypt(ssl_mode, r_k, 1, encrypt_cbc_block);
}