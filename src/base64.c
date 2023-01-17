#include "ft_ssl.h"
#include "libft.h"

char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

unsigned char  what_in_my_b64(int b64_c)
{
    for (int i = 0; i < 65; i++)
    {
        if (b64_c == b64_charset[i])
            return i;
    }
}

ssize_t b64_to_three_bytes(char *raw_input, char *dest, ssize_t readed, int print, int fd)
{
    // raw_input size is 4
    // output size is 3
    
    unsigned char input[4];
    unsigned char output[4];
    int i = 0, j = 0;
    ssize_t result_size = readed;

    for (; i < readed; i += 4, j += 3)
    {
        ft_bzero(output, 4);
        ft_bzero(input, 4);
        ft_memcpy(input, raw_input + i, 4);

        for (int i = 0; i < 4; i++)
        {
            if (input[i] == b64_charset[64])
            {
                // printf("here lol\n");
                input[i] = 0;
                result_size--;
            } else
                input[i] = what_in_my_b64(input[i]);
        }

        output[0] = (input[0] << 2) | (input[1] >> 4);
        output[1] = input[1] << 4 | input[2] >> 2; 
        output[2] = input[2] << 6 | (input[3]);

        if (print == 1 && fd > 0) write(fd, &output, 3);
        else ft_memcpy(dest + j, output, 3);
    }
    return result_size;
}

void three_bytes_to_b64(char *raw_input, ssize_t readed, int print, int fd)
{
    // raw_input size is between 1 to 3
    // output size is 4

    unsigned char input[3];
    unsigned char output[4];

    for (int i = 0; i < readed; i += 3)
    {
        // printf("i: %d\n", i);
        // if (i > 8)
        // {      
        //     printf("%c", input[0]);
        //     printf("%c", input[1]);
        //     printf("%c", input[2]);
        // }
        ft_bzero(output, 4);
        ft_bzero(input, 3);

        ft_memcpy(input, raw_input + i, 3);

        // process three bytes to four bytes
        output[0] = b64_charset[(input[0] >> 2) & 0b00111111];

        output[1] = b64_charset[((input[0] << 4) | (input[1] >> 4)) & 0b00111111];


        // Apply padding
        if ((i + 3) == readed + 2) {
            output[2] = b64_charset[64];
            output[3] = b64_charset[64];
        }
        else if ((i + 3) == readed + 1) {
            output[2] = b64_charset[(input[1] << 2 | input[2] >> 6) & 0b00111111];
            output[3] = b64_charset[64];
        } else {
            output[2] = b64_charset[(input[1] << 2 | input[2] >> 6) & 0b00111111];
            output[3] = b64_charset[input[2] & 0b00111111];
        }

        write(fd, &output, 4);
    }
}

void    base64_process_dispatch(t_ft_ssl_mode *ssl_mode, int char_size)
{
    unsigned char tmp[4], output[4];
    int readed = 0;
    
    while ((readed = utils_read(ssl_mode->input_fd, tmp, char_size, ssl_mode->decode_mode)) > 0)
    {
        if (char_size == 4) b64_to_three_bytes(tmp, output, readed, 1, ssl_mode->output_fd); // decode
        else  three_bytes_to_b64(tmp, readed, 0, ssl_mode->output_fd); // encode
    }

    if (readed < 0)
        print_errors(ERROR_READ_GLOBAL, ssl_mode);

    putchar('\n');
}


void    base64_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    if (ssl_mode->decode_mode == 1) base64_process_dispatch(ssl_mode, 4); // decode
    else  base64_process_dispatch(ssl_mode, 3); // encode
}
