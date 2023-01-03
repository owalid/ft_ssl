#include "ft_ssl.h"
#include "libft.h"

char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";


unsigned char* three_bytes_to_b64(unsigned char *raw_input, unsigned char *output)
{
    // Input size is between 1 to 3
    // Result size is 4
    char padding;
    char input[4];

    ft_memcpy(input, raw_input, 4);

    int len_input = ft_strlen(input);

    ft_bzero(output, 4);
    ft_memcpy(output, input, len_input);

    // process three bytes to four bytes
    
    output[0] = b64_charset[(input[0] >> 2) & 0b00111111];
    output[1] = b64_charset[((input[0] << 4) | ((input[1] >> 4))) & 0b00111111];

    // Apply padding
    if (len_input == 1) {
        output[2] = b64_charset[64];
        output[3] = b64_charset[64];
    }
    else if (len_input == 2) {
        output[2] = b64_charset[(input[1] << 2 | input[2] >> 6) & 0b00111111];
        output[3] = b64_charset[64];
    } else {
        output[2] = b64_charset[(input[1] << 2 | input[2] >> 6) & 0b00111111];
        output[3] = b64_charset[input[2] & 0b00111111];
    }
    
    return output;
}

void    base64_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    printf("input => %s\n", input);
    
    int len_input = ft_strlen(input);
    unsigned char tmp[4];
    // ft_bzero(tmp, 4);
    int i = 0;
    // printf("[strlen]: %d\n", len_input);

    while (i < len_input)
    {
        // printf("[i] %d\n", i);
        ft_bzero(tmp, 4);
        three_bytes_to_b64(input + i, tmp);
        ft_putstr(tmp);

        i+=3;
    }
    putchar('\n');
}