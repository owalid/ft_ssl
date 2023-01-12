#include "ft_ssl.h"
#include "libft.h"

void        des_ecb_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    unsigned long r_k[16];

    ft_bzero(r_k, 16*8);

    // process round key
    process_round_keys(ssl_mode->key, r_k);

    // display_key(r_k);

    if (ssl_mode->decode_mode == 1) des_decrypt(ssl_mode, r_k, 0);
    else des_encrypt(ssl_mode, r_k, 0);
}