#include "libft.h"
#include "ft_ssl.h"
#include "ft_ssl_op.h"

int main(int argc, char **argv) {
    if (argc > 2) {
        for (int i = 0; i < SIZE_OP; i++) {
            if (ft_strcmp(argv[1], g_ftssl_op[i].name) == 0) {
                g_ftssl_op[i].ft_ssl_process(argv[2]);
            }
        }
    }
}