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
    unsigned int t_i[8];
    unsigned int result[8];
    unsigned int final_result[8];
    unsigned int res_res[dk_len*8];
    unsigned int concat_int[2];
    unsigned int swap_l;


    ft_bzero(concat_int, 8+4);

    int size_password = ft_strlen(password);
    int total_len_concat = 4+8; // size password + 1 int + 8*4 uint
    
    char concat_str[12]; // 12 = 4 + 8 (1 int + 1 long)

    ft_bzero(concat_str, total_len_concat);

    unsigned long swapped_salt = swap64(salt);
    print_hex(&swapped_salt, 8);

    dk_len = (dk_len == 0) ? 1 : dk_len;
    ft_bzero(final_result, 8*4);
    for (int l = 1; l <= dk_len; l++)
    {
        swap_l = swap32(l);
        print_hex(&swap_l, 4);
        // concatenate password with (concatenate of salt with l)
        ft_bzero(concat_str, total_len_concat);
        ft_memcpy(concat_str, &swapped_salt, 8);
        ft_memcpy(concat_str + 8, &swap_l, 4);
        print_hex(concat_str, 12);
        hmac_sha256(concat_str, password, size_password, 8+4, result);
        
        for (int i = 0; i < 8; i++)
            final_result[i] = result[i];

        print_hex(final_result, 32);
        // print_hex(result, 32);
        

        // for (int i = 1; i < 1; i++) // process F function
        // {
        //     // concatenate password with last_u
        //     hmac_sha256(password, result, 8*4, result);
            
        //     // xor result to optain T
        //     for (int i = 0; i < 8; i++)
        //         t_i[i] ^= result[i];
        // }

        // // concatenate all T
        // for (int i = 0; i < 8; i++)
        //     final_result[i] = t_i[i];
    }
    // free(concat_str);

    // print_hashes_64(result, 8);
    // printf("\n\nwithout key, without pass:\n");
    // printf("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad\n\n");
    // printf("without key, with pass lol:\n");
    // printf("ed094d614919a055e78dc191fb658b9b0e7b24d0d05eb421211eecdc37ebb566\n");
    // printf("\n");
    // printf("my result:\n");
    // print_hash_32(result, 8);
    printf("\n\n");
    printf("should_have =\t6C07F78FECD825FE\n");
    printf("my_key =\t%s%s\n", ft_utoa_base(final_result[0], 16), ft_utoa_base(final_result[1], 16));
    // printf("result[1] = %s \n", ft_utoa_base(result[1], 16));
    exit(1);
    *key = result[0];
    *iv = result[1];
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
        char tmp_password[4096];
        char *stdin_password = tmp_password;

        ft_bzero(stdin_password, 4096);
        stdin_password = getpass("Enter encryption password: ");
        len_pass = ft_strlen(stdin_password);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for sha512

        process_rounds(stdin_password, salt_number, tdk_len, &tmp_key, &tmp_iv);
        free(stdin_password);
    } else {
        len_pass = ft_strlen(pass);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for sha512
        process_rounds(pass, salt_number, tdk_len, &ssl_mode->key, &tmp_iv);
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
        print_hash_64(salt_number, 0);
        // ft_putstr("\nkey=");
        // print_hash_64(tmp_key, 0);
        if (need_gen_iv)
        {
            ft_putstr("\niv=");
            print_hash_64(ssl_mode->iv, 0);
        }
        ft_putchar('\n');
        exit(0);
    }
}