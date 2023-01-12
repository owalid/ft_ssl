# include "libft.h"
# include "ft_ssl.h"
// Password-Based Key Derivation Function

char hex_characters[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

void    generate_salt(char *salt)
{
    printf("\ninside here");
    for (int i = 0; i < 16; i++)
        salt[i] = rand() % 256;
}

unsigned long   process_rounds(char *password, unsigned long salt, int dk_len)
{
    unsigned long t_i = 0;
    unsigned long result;
    unsigned long last_u;
    int size_password = ft_strlen(password);
    int total_len_concat = size_password + 8 + 16;
    // char *tmp_concat_str = 
    // unsigned long size_dk_str_len = ft_strlen(ft_itoa(dk_len));
    char *concat_str = ft_strnew(total_len_concat);

    ft_bzero(concat_str, total_len_concat);
    ft_memcpy(concat_str, password, size_password);
    for (int l = 0; l < dk_len; l++)
    {
        // concatenate password with (concatenate of salt with l)
        ft_memcpy(concat_str + size_password, &salt, 16);
        ft_memcpy(concat_str + size_password + 16, &l, 8);
        last_u = simple_sha256(concat_str);
        t_i = last_u;

        for (int i; i < 4096; i++)
        {
            // concatenate password with last_u
            ft_bzero(concat_str, total_len_concat);
            ft_memcpy(concat_str, password, size_password);
            ft_memcpy(concat_str + size_password, &last_u, total_len_concat);
            last_u = simple_sha256(concat_str);
            t_i ^= last_u;
        }
        
        result += t_i;
    }

    free(concat_str);

    return result;
}

// DK = PBKDF2(PRF, Password, Salt, c, dkLen)
unsigned long    process_pbkdf(char *pass, char *raw_salt, int stdin_mode)
{
    char salt_str[17];
    unsigned long salt_number = 0;
    unsigned long result = 0;
    unsigned long last_u = 0;
    unsigned long derived_key = 0;
    int tdk_len = 0;
    int c = 4096;
    int h_len = 256;
    int len_pass = 0;

    srand(time(NULL));

    ft_bzero(salt_str, 17);

    // printf("raw_salt: %lu", (unsigned long)raw_salt);
    if (raw_salt != 0)
    {
        ft_memcpy(salt_str, raw_salt, 16);
        salt_number = ft_hextol(salt_str);
    } else {
        generate_salt(salt_str);
        ft_memcpy(&salt_number, salt_str, 16);
    }

    printf("\nraw_salt: %s", raw_salt);
    printf("\nsalt: %s\n", salt_str);

    // salt_number = (unsigned long)salt_str;
    printf("\nsalt_number: %lu\n", salt_number);

    if (stdin_mode)
    {
        // todo need to read
        char tmp_password[4096];
        char *stdin_password = tmp_password;

        ft_bzero(stdin_password, 4096);
        stdin_password = getpass("Enter encryption password");
        printf("stdin_password: %s", stdin_password);
        len_pass = ft_strlen(stdin_password);
        free(stdin_password);
    } else {
        len_pass = ft_strlen(pass);
        tdk_len = (len_pass / 256) + ((len_pass%256) % 2); // get len of blocks for sha256

        printf("tdk_len: %d\n", tdk_len);
        derived_key = process_rounds(pass, salt_number, tdk_len);
        printf("derived_key:\t%s\n", ft_utoa_base(derived_key, 16));
        printf("salt:\t\t%s\n", ft_utoa_base(salt_number, 16));
        // printf()
        // result = process_one_round(pass, salt, 1);
        // for (int t = 0; t < tdk_len; t++)
        // {
        //     // result = process_one_round(salt);
        // }
    }



    // for (int t = 0; t < tdk_len; t++)
    // {
    //     // last_u = PRF(Password, Salt || INT_32_BE(c))
    //     result = last_u;
    //     for (int i = 0; i < 4096; i++)
    //     {
    //         // last_u = PRF(Password, last_u);
    //         // result ^= last_u
    //     }

    //     // derived_key = ; concatenate derived keys
    //     result = 0;
    // }

    if (stdin_mode) {
        // todo 
        // display as 
        // salt=
        // key=
        // and exit
        exit(0);
    }
}