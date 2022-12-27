#include "libft.h"
#include "ft_ssl.h"
#include "ft_ssl_op.h"


t_ft_ssl_mode* ft_search_modes(char **argv, int argc, t_ft_ssl_mode *ssl_mode) {
    for (int i = 0; i < argc; i++) {
        if (ft_strcmp(argv[i], "-q") == 0) {
            ssl_mode->quiet_mode = 1;
        } else if (ft_strcmp(argv[i], "-r") == 0) {
            ssl_mode->reverse_mode = 1;
        } else if (ft_strcmp(argv[i], "-p") == 0) {
            ssl_mode->std_mode = 1;
        }
    }
}

int main(int argc, char **argv) {
    if (argc > 1) {
        for (int i = 0; i < SIZE_OP; i++) {
            if (ft_strcmp(argv[1], g_ftssl_op[i].name) == 0) { // get name of digest algorithm
                t_ft_ssl_mode ssl_mode[1];
                ft_search_modes(argv, argc, ssl_mode); // extract modes options
                int flag_process = 0;
                int j = 2;

                for (; j < argc; j++) {
                    if (ft_strcmp(argv[j], "-p") == 0) {
                        j++;
                        break;
                    }
                    if (ft_strstr(argv[j], "-") == NULL && ft_strcmp(argv[j-1], "-s") != 0) // check if is a file
                        break;
                    if (ft_strcmp(argv[j], "-s") == 0 && (j + 1) < argc) { // process as string
                        g_ftssl_op[i].ft_ssl_process(argv[j + 1], ssl_mode, 0, g_ftssl_op[i].name);
                        flag_process = 1;
                        j += 2; // pass -s and string
                    }
                }
                for (; j < argc; j++) { // process as files
                    g_ftssl_op[i].ft_ssl_process(argv[j], ssl_mode, 1, g_ftssl_op[i].name);
                    flag_process = 1;
                }

                if (flag_process == 0 || ssl_mode->std_mode == 1) {
                    g_ftssl_op[i].ft_ssl_process(NULL, ssl_mode, 2, g_ftssl_op[i].name);
                }
            }
        }
    }
}