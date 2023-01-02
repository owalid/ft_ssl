#include "ft_ssl.h"
#include "libft.h"

char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


unsigned char* bytes_split(unsigned char *input) {
    
    int len_input = ft_strlen(input);
    unsigned char* result = ft_strnew(4);
    int curr = 0;
    int next = 0;
    int l = 0;
    int r = 0;

    ft_bzero(result, len_input*sizeof(unsigned char));

    for (int u = 0; u < len_input; u++)
    {
        result[u] = ((input[u] & (0b111111 << 2)) >> 2);
        
        // r = input[u] - result[u];
        // print_bit(r);
    }
    printf("\n");
    return result;
}

void    base64_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name)
{
    printf("input => %s\n", input);
    
    int len_input = ft_strlen(input);
    char *lol = ft_strnew(len_input*8);
    // for (int l=0; l < len_input*8; l+=8) {
        // for (int j=6; j>6; j++) {
            // ft_memccpy(&lol, (input[l] >> j) & 1, )
        // }
    //     ft_memccpy(&lol, (n >> i) & 1, )
    // }
    unsigned char* res = bytes_split(input);
    // printf("lollol => %ls\n", res);
    for (int i = 0; i < len_input; i++) {
        // unsigned char lolmdr = (input[i] & (0b111111 << 2)) >> 2;
        // // unsigned int lolmdr = input[i] & (0b111111 << 2);
        // printf("%c =>\n", input[i]);
        // // printf("")
        // printf("%d => %c\n", lolmdr, b64_charset[lolmdr]);
        // printf("%d => %c\n", res[i], b64_charset[res[i]]);

        // print_bit(res[i]);
        // printf("010011\n");
        // print_bit(res[i]);
        // printf("\n");
        // print_bit(lolmdr);
        // printf("\n");
        // print_bit(input[i]);
        // printf("\n");
    }
    printf("\n");
}