#include "ft_ssl.h"
#include "libft.h"
#include <stdio.h>

void    sha384_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type)
{

    unsigned long vars[] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 
                                0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };
    fn_process(input, input_type, 128, vars, 1, sha512_process_firsts_blocks);
    print_hash_64(vars, 6);

    // printf("\n%016lx%016lx%016lx%016lx%016lx%016lx\n",vars[0], vars[1], vars[2], vars[3], vars[4], vars[5]);
}