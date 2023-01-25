# include "libft.h"
# include "ft_ssl.h"
// Password-Based Key Derivation Function

void    generate_salt(char *salt)
{
    for (int i = 0; i < 16; i++)
        salt[i] = rand() % 256;
}

void   process_rounds(char *password, unsigned long salt, int dk_len, unsigned long *key, unsigned long *iv, t_ft_ssl_mode *ssl_mode)
{
    char concat_str[12]; // 12 = 4 + 8 (1 int + 1 long)
    unsigned int t_i[8];
    unsigned int round_result[8];
    unsigned long swapped_salt = swap64(salt);
    unsigned int swap_l = 0;
    char clean_password[64];
    int size_password = ft_strlen(password);
    int total_len_concat = 4+8; // size password + 1 int + 8*4 uint
    
    dk_len = (dk_len == 0) ? 1 : dk_len;

    ft_bzero(clean_password, 64);
    ft_bzero(concat_str, total_len_concat);
    ft_bzero(round_result, 8*4);
    ft_bzero(t_i, 8*4);

    ssl_mode->iter_number = (ssl_mode->iter_number > 0) ? ssl_mode->iter_number : 4096;

    if (size_password > 64)
    {
        unsigned int vars[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        fn_process(password, 0, 64, vars, 1, sha256_process_firsts_blocks, ssl_mode, NULL);
        unsigned int tmp_var = 0;

        for (int i = 0; i < 8; i++)
        {
            tmp_var = swap32(vars[i]);
            ft_memcpy(clean_password + (i*4), &tmp_var, 4);
        }
        size_password = 32;
    } else
        ft_memcpy(clean_password, password, size_password);

    for (int l = 1; l <= 1; l++)
    {
        swap_l = swap32(l);

        // concatenate password with (concatenate of salt with l)
        ft_bzero(concat_str, total_len_concat);
        ft_memcpy(concat_str, &swapped_salt, 8);
        ft_memcpy(concat_str + 8, &swap_l, 4);

        hmac_sha256(concat_str, clean_password, 8+4, round_result);
        
        for (int i = 0; i < 8; i++)
            t_i[i] = round_result[i];

        for (int i = 1; i < ssl_mode->iter_number; i++) // process F function
        {
            // concatenate password with last_u
            hmac_sha256((char *)round_result, clean_password, 8*4, round_result);
            
            // xor round_result to optain T
            for (int i = 0; i < 8; i++)
                t_i[i] ^= round_result[i];
        }
        

        // concatenate all T
        for (int i = 0; i < 8; i++)
            round_result[i] = t_i[i];
    }

    *key = round_result[0] | ((unsigned long)round_result[1] << 32);
    *key = swap64(*key);
    *iv = round_result[2] | ((unsigned long)round_result[3] << 32);
    *iv = swap64(*iv);
}

// DK = PBKDF2(PRF, Password, Salt, c, dkLen)
void    process_pbkdf(char *pass, char *raw_salt, t_ft_ssl_mode *ssl_mode, int need_gen_iv)
{
    char salt_str[17];
    unsigned long tmp_iv = 0, salt_number = 0;
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

        process_rounds(stdin_password, salt_number, tdk_len, &ssl_mode->key, &tmp_iv, ssl_mode);
        free(stdin_password);
    } else {
        len_pass = ft_strlen(pass);
        process_rounds(pass, salt_number, tdk_len, &ssl_mode->key, &tmp_iv, ssl_mode);
    }


    if (need_gen_iv && !ssl_mode->have_iv)
        ssl_mode->iv = tmp_iv;

    ssl_mode->salt = swap64(salt_number);

    // display as 
    // salt=...
    // key=...
    // iv=...
    ft_putstr_fd("salt=", 2);
    print_hash_64(salt_number, 0, 0, 2);
    ft_putstr_fd("\nkey=", 2);
    print_hash_64(ssl_mode->key, 0, 0, 2);
    if (need_gen_iv)
    {
        ft_putstr_fd("\niv=", 2);
        print_hash_64(ssl_mode->iv, 0, 0, 2);
    }
    ft_putchar_fd('\n', 2);
    
    if (ssl_mode->print_key_exit)
        exit(0);
}