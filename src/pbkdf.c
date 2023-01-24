# include "libft.h"
# include "ft_ssl.h"
// Password-Based Key Derivation Function

void    generate_salt(char *salt)
{
    for (int i = 0; i < 16; i++)
        salt[i] = rand() % 256;
}


// echo "lol" | ./ft_ssl des-ecb -s "1F3A6C95CE34681E"
// echo "lol" | openssl des-ecb -P -pass "pass:lol" -provider legacy -provider default -S "1F3A6C95CE34681E" -iter 1 -pbkdf2
void   process_rounds(char *password, unsigned long salt, int dk_len, unsigned long *key, unsigned long *iv)
{
    char concat_str[12]; // 12 = 4 + 8 (1 int + 1 long)
    unsigned int t_i[8];
    unsigned int round_result[8];
    unsigned long swapped_salt = swap64(salt);
    unsigned int swap_l = 0;

    int size_password = ft_strlen(password);
    int total_len_concat = 4+8; // size password + 1 int + 8*4 uint
    
    dk_len = (dk_len == 0) ? 1 : dk_len;

    ft_bzero(concat_str, total_len_concat);
    ft_bzero(round_result, 8*4);
    ft_bzero(t_i, 8*4);

    for (int l = 1; l <= dk_len; l++)
    {
        swap_l = swap32(l);

        // concatenate password with (concatenate of salt with l)
        ft_bzero(concat_str, total_len_concat);
        ft_memcpy(concat_str, &swapped_salt, 8);
        ft_memcpy(concat_str + 8, &swap_l, 4);

        hmac_sha256(concat_str, password, size_password, 8+4, round_result);
        
        for (int i = 0; i < 8; i++)
            t_i[i] = round_result[i];

        for (int i = 1; i < 4096; i++) // process F function
        {
            // concatenate password with last_u
            hmac_sha256((char *)round_result, password, size_password, 8*4, round_result);
            
            // xor round_result to optain T
            for (int i = 0; i < 8; i++)
                t_i[i] ^= round_result[i];
        }


        // concatenate all T
        for (int i = 0; i < 8; i++)
            round_result[i] = t_i[i];
    }

    *key = swap32(round_result[1]) | ((unsigned long)swap32(round_result[0]) << 32);
    *iv = swap32(round_result[3]) | ((unsigned long)swap32(round_result[2]) << 32);
}

// DK = PBKDF2(PRF, Password, Salt, c, dkLen)
void    process_pbkdf(char *pass, char *raw_salt, t_ft_ssl_mode *ssl_mode, int need_gen_iv)
{
    char salt_str[17];
    unsigned long tmp_key = 0, tmp_iv = 0, salt_number = 0;
    int tdk_len = 0, len_pass = 0;

    srand(time(NULL));
    ft_bzero(salt_str, 17);

    if (raw_salt != 0)
    {
        ft_memcpy(salt_str, raw_salt, 16);
        salt_number = ft_hextol(salt_str);
    } else {
        generate_salt(salt_str);
        ft_memcpy(&salt_number, salt_str, 16);
    }

    if (!ssl_mode->have_password) // if not have password read as stdin
    {
        char *stdin_password;

        stdin_password = getpass("Enter encryption password: ");
        len_pass = ft_strlen(stdin_password);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for hmac-sha256

        process_rounds(stdin_password, salt_number, tdk_len, &ssl_mode->key, &tmp_iv);
        free(stdin_password);
    } else {
        len_pass = ft_strlen(pass);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for hmac-sha256
        process_rounds(pass, salt_number, tdk_len, &ssl_mode->key, &tmp_iv);
        // exit(0);
    }


    if (need_gen_iv && !ssl_mode->have_iv)
            ssl_mode->iv = tmp_iv;

    if (ssl_mode->print_key_exit)
    {
        // display as 
        // salt=...
        // key=...
        // iv=...
        ft_putstr("salt=");
        print_hash_64(salt_number, 0, 0);
        ft_putstr("\nkey=");
        print_hash_64(ssl_mode->key, 0, 1);
        if (need_gen_iv)
        {
            ft_putstr("\niv=");
            print_hash_64(ssl_mode->iv, 0, 1);
        }
        ft_putchar('\n');
        exit(0);
    }
}