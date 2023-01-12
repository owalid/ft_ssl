# include "libft.h"
# include "ft_ssl.h"
// Password-Based Key Derivation Function

void    generate_salt(char *salt)
{
    for (int i = 0; i < 16; i++)
        salt[i] = rand() % 256;
}

unsigned long   process_rounds(char *password, unsigned long salt, int dk_len)
{
    unsigned long t_i = 0;
    unsigned long result = 0;
    unsigned long last_u = 0;
    int size_password = ft_strlen(password);
    int total_len_concat = size_password + 4 + 8; // size password + 1 int + 1 long
    char *concat_str = ft_strnew(total_len_concat);

    dk_len = (dk_len == 0) ? 1 : dk_len;

    for (int l = 1; l <= dk_len; l++)
    {
        // concatenate password with (concatenate of salt with l)
        ft_bzero(concat_str, total_len_concat + 1);
        ft_memcpy(concat_str, password, size_password);
        ft_memcpy(concat_str + size_password, &salt, 8);
        ft_memcpy(concat_str + size_password + 8, &l, 4);

        last_u = simple_sha512(concat_str);

        t_i = last_u;

        for (int i = 0; i < 4096; i++)
        {
            // concatenate password with last_u
            ft_bzero(concat_str, total_len_concat);
            ft_memcpy(concat_str, password, size_password);
            ft_memcpy(concat_str + size_password, &last_u, 64);
            last_u = simple_sha512(concat_str);
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

    // printf("%s\n", raw_salt);
    if (raw_salt != 0)
    {
        ft_memcpy(salt_str, raw_salt, 16);
        salt_number = ft_hextol(salt_str);
    } else {
        generate_salt(salt_str);
        ft_memcpy(&salt_number, salt_str, 16);
    }

    if (stdin_mode)
    {
        // todo need to read
        char tmp_password[4096];
        char *stdin_password = tmp_password;

        ft_bzero(stdin_password, 4096);
        stdin_password = getpass("Enter encryption password");
        len_pass = ft_strlen(stdin_password);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for sha512

        derived_key = process_rounds(stdin_password, salt_number, tdk_len);
        free(stdin_password);
    } else {
        len_pass = ft_strlen(pass);
        tdk_len = ((len_pass / 128) == 0) ? 1 : (len_pass / 128); // get len of blocks for sha512
        printf("\ntdk_len: %u|", tdk_len);
        printf("len_pass: %d", len_pass);
        derived_key = process_rounds(pass, salt_number, tdk_len);
        // print_hash_64(derived_key, 0);
        return derived_key;
    }

    if (stdin_mode) {
        // display as 
        // salt=...
        // key=...
        ft_putstr("salt=");
        print_hash_64(salt_number, 0);
        ft_putstr("\nkey=");
        print_hash_64(derived_key, 0);
        ft_putchar('\n');
        exit(0);
    }
}