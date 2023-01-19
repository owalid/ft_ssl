# include "libft.h"
# include "ft_ssl.h"
// Password-Based Key Derivation Function

void    generate_salt(char *salt)
{
    for (int i = 0; i < 16; i++)
        salt[i] = rand() % 256;
}

void   process_rounds(char *password, unsigned long salt, int dk_len, unsigned long *key, unsigned long *iv)
{
    unsigned long t_i[2];
    unsigned long result[2];
    int size_password = ft_strlen(password);
    int total_len_concat = size_password + 4 + 8*2; // size password + 1 int + 2 long
    char *concat_str = ft_strnew(total_len_concat);

    dk_len = (dk_len == 0) ? 1 : dk_len;

    for (int l = 1; l <= dk_len; l++)
    {
        // concatenate password with (concatenate of salt with l)
        ft_bzero(concat_str, total_len_concat + 1);
        ft_memcpy(concat_str, password, size_password);
        ft_memcpy(concat_str + size_password, &salt, 8);
        ft_memcpy(concat_str + size_password + 8, &l, 4);

        simple_sha512(concat_str, result);
        t_i[0] = result[0];
        t_i[1] = result[1];

        for (int i = 0; i < 4096; i++) // process F function
        {
            // concatenate password with last_u
            ft_bzero(concat_str, total_len_concat);
            ft_memcpy(concat_str, password, size_password);
            ft_memcpy(concat_str + size_password, &result[0], 8);
            ft_memcpy(concat_str + size_password + 8, &result[1], 8);
            simple_sha512(concat_str, result);
            t_i[0] ^= result[0];
            t_i[1] ^= result[1];
        }
        
        result[0] += t_i[0];
        result[1] += t_i[1];
    }
    free(concat_str);

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

        // display as 
        // salt=...
        // key=...
        // iv=...
        ft_putstr("salt=");
        print_hash_64(salt_number, 0);
        ft_putstr("\nkey=");
        print_hash_64(tmp_key, 0);
        if (need_gen_iv)
        {
            if (!ssl_mode->have_iv)
                ssl_mode->iv = tmp_iv;

            ft_putstr("\niv=");
            print_hash_64(ssl_mode->iv, 0);
            ft_putchar('\n');
        }
        free(stdin_password);
        exit(0);
    } else {
        len_pass = ft_strlen(pass);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for sha512
        process_rounds(pass, salt_number, tdk_len, &ssl_mode->key, &tmp_iv);

        if (need_gen_iv && !ssl_mode->have_iv)
            ssl_mode->iv = tmp_iv;
    }
}