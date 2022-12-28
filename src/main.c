#include "libft.h"
#include "ft_ssl.h"
#include "ft_ssl_op.h"


void ft_search_modes(char **argv, int argc, t_ft_ssl_mode *ssl_mode) {
    for (int i = 0; i < argc; i++) {
        // todo check options not found
        if (ft_strcmp(argv[i], "--") == 0)
            break;
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
    int flag = 0;
    int s_flag = 0; // check if we have already an -s options
    if (argc <= 3) {
        if ((argc == 2 && ft_strcmp(argv[1], "-list") == 0) || (argc == 3 && ft_strcmp(argv[2], "-list") == 0)) {
            ft_putstr(ALGO_LIST);
            exit(0);
        } else if (ft_strcmp(argv[1], "-help") == 0 || (argc == 3 && ft_strcmp(argv[2], "-help") == 0)) {
            ft_putstr(USAGE);
            exit(0);
        }
    }
    if (argc >= 2) {
        for (int i = 0; i < SIZE_OP; i++) {
            if (ft_strcmp(argv[1], g_ftssl_op[i].name) == 0) { // get name of digest algorithm
                flag = 1;
                t_ft_ssl_mode ssl_mode[1];
                ft_bzero(&ssl_mode, sizeof(t_ft_ssl_mode));
                ft_search_modes(argv, argc, ssl_mode); // extract modes options
                int flag_process = 0;
                int j = 2;

                for (; j < argc; j++) {
                    if (ft_strcmp(argv[j], "--") == 0) {
                        j++;
                        break;
                    }
                    if (ft_strstr(argv[j], "-") == NULL) // check if is a file
                        break;
                    if (ft_strcmp(argv[j], "-s") == 0) { // process as string
                        if (argc < (j + 1) || !argv[j+1]) {
                            ft_putstr(ERROR_STR_OPT);
                            exit(1);
                        }
                        if (s_flag == 0) {
                            g_ftssl_op[i].ft_ssl_process(argv[j + 1], ssl_mode, 0, g_ftssl_op[i].name);
                            flag_process = 1;
                            s_flag = 1;
                        }
                        j++; // pass -s and string
                    }
                }
                for (; j < argc; j++) { // process as files
                    g_ftssl_op[i].ft_ssl_process(argv[j], ssl_mode, 1, g_ftssl_op[i].name);
                    flag_process = 1;
                }
                if (flag_process == 0 || ssl_mode->std_mode == 1)
                    g_ftssl_op[i].ft_ssl_process(NULL, ssl_mode, 2, g_ftssl_op[i].name);
            }
        }
        if (flag == 0) {
            ft_putstr(ERROR_ALGO_1);
            ft_putstr(argv[1]);
            ft_putstr(ERROR_ALGO_2);
            ft_putchar('\n');
        }
    } else {
        ft_putstr(USAGE);
    }
}