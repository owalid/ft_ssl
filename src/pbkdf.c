# include "libft.h"
// Password-Based Key Derivation Function

char hex_characters[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

void    generate_salt(char *salt)
{
    for (int i = 0; i < 16; i++)
        salt[i] = hex_characters[rand() % 15];
}

unsigned long   process_one_round(unsigned long salt)
{
    unsigned long result = 0;
    // unsigned long last_u = ;

    for (int i = 0; i < 4096; i++)
    {
        // last_u = PRF(Password, last_u);
        // result ^= last_u
    }
    return result;
}

// DK = PBKDF2(PRF, Password, Salt, c, dkLen)
unsigned long    process_pbkdf(char *pass, char *raw_salt, int stdin_mode)
{
    char salt[17];
    unsigned long salt_number = 0;
    unsigned long result = 0;
    unsigned long last_u = 0;
    unsigned long derived_key = 0;
    int c = 4096;
    int h_len = 256;
    int len_pass = 0;
    
    if (stdin_mode)
    {
        // todo need to read

    } else {
        len_pass = ft_strlen(pass);
        int tdk_len = (len_pass / 256) + ((len_pass%256) % 2); // get len of blocks for sha256

        for (int t = 0; t < tdk_len; t++)
        {
            // result = process_one_round(salt);
        }    
    }


    ft_bzero(salt, 17);

    if ((unsigned long)raw_salt == 0)
        ft_memcpy(salt, raw_salt, 16);
    else
        generate_salt(salt);

    salt_number = ft_hextol(salt);

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