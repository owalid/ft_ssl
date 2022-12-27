#include "ft_ssl.h"
#include "libft.h"
#include <stdio.h>

void    sha224_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type)
{
    unsigned int vars[] = { 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };
    fn_process(input, input_type, 64, vars, 1, sha256_process_firsts_blocks);
    print_hash_32(vars, 7);

    // printf("\n%08x%08x%08x%08x%08x%08x%08x \n",vars[0], vars[1], vars[2], vars[3], vars[4], vars[5], vars[6]);
}