#include "libft.h"
#include "ft_ssl.h"
#include "ft_ssl_op.h"


void ft_search_modes(char **argv, int argc, t_ft_ssl_mode *ssl_mode) {
    for (int i = 2; i < argc; i++) { // search for -q, -r, -p, -s options and -- to stop options
        if (ft_strcmp(argv[i], "--") == 0)
            break;
        if (ft_strcmp(argv[i], "-q") == 0) {
            ssl_mode->quiet_mode = 1;
        } else if (ft_strcmp(argv[i], "-r") == 0) {
            ssl_mode->reverse_mode = 1;
        } else if (ft_strcmp(argv[i], "-p") == 0) {
            ssl_mode->std_mode = 1;
        } else if (ft_strcmp(argv[i], "-s") == 0 || ft_strcmp(argv[i], "-i") == 0
                    || ft_strcmp(argv[i], "-o") == 0 || ft_strcmp(argv[i], "-k") == 0) { // need to be process after
            i++;
            continue;
        } else if (ft_strcmp(argv[i], "-d") == 0) {
            ssl_mode->decode_mode = 1;
        } else if (ft_strcmp(argv[i], "-e") == 0) {
            ssl_mode->encode_mode = 1;
        } else if (ft_strcmp(argv[i], "-a") == 0) {
            ssl_mode->des_b64 = 1;
        } else if (argv[i][0] == '-') {
            ft_putstr("option: '");
            ft_putstr(argv[i]);
            ft_putstr("'. Not found.\n");
            exit(1);
        } 
    }
}

unsigned long gen_key_padding(char *raw_k, char *dest_key)
{
    ssize_t result_hex = 0;
    int len_key = ft_strlen(raw_k);
    ft_bzero(dest_key, 17);
    ft_memset(dest_key, '0', 16);
    ft_memcpy(dest_key, raw_k, (len_key > 16) ? 16 : len_key); // ignoring excess after len 16

    result_hex = ft_hextol(dest_key);

    if (result_hex == -1 || len_key < 0)
    {
        ft_putstr(ERROR_DES_NO_HEX);
        exit(1);
    } else if (len_key < 16) ft_putstr(WARNING_DES_KEY_TO_SHORT);
    else if (len_key > 16) ft_putstr(WARNING_DES_KEY_TO_LONG);

    return result_hex;
}

int main(int argc, char **argv) {
    int flag = 0;
    int s_flag = 0; // check if we have already an -s options
    int op_dig_size = sizeof(g_ftssl_digest_op) / sizeof(g_ftssl_digest_op[0]); // get size of array of digest algorithms
    int op_des_size = sizeof(g_ftssl_des_op) / sizeof(g_ftssl_des_op[0]); // get size of array of digest algorithms

    t_ft_ssl_mode ssl_mode[1];
    ft_bzero(&ssl_mode, sizeof(t_ft_ssl_mode));

    if (argc == 3 || argc == 2) { // display -list and -help options
        if ((argc == 2 && ft_strcmp(argv[1], "-list") == 0) || (argc == 3 && ft_strcmp(argv[2], "-list") == 0)) {
            ft_putstr(ALGO_LIST);
            exit(0);
        } else if (ft_strcmp(argv[1], "-help") == 0 || (argc == 3 && ft_strcmp(argv[2], "-help") == 0)) {
            ft_putstr(USAGE);
            exit(0);
        }
    }
    if (argc >= 2) {
        for (int i = 0; i < op_dig_size; i++) {
            if (ft_strcmp(argv[1], g_ftssl_digest_op[i].name) == 0) { // get name of digest algorithm
                flag = 1;
                // printf("lol");
                ft_search_modes(argv, argc, ssl_mode); // extract modes options
                int flag_process = 0;
                int j = 2;

                for (; j < argc; j++) {
                    if (ft_strcmp(argv[j], "--") == 0) { // stop options and process the rest as files
                        j++;
                        break;
                    }
                    if (argv[j][0] != '-') // check if is a file 
                        break;
                    if (ft_strcmp(argv[j], "-s") == 0) { // process as string
                        if (argc < (j + 1) || !argv[j+1]) {
                            ft_putstr(ERROR_STR_OPT);
                            exit(1);
                        }
                        if (s_flag == 0) {
                            g_ftssl_digest_op[i].ft_ssl_process(argv[j + 1], ssl_mode, 0, g_ftssl_digest_op[i].name);
                            flag_process = 1;
                            s_flag = 1;
                        }
                        j++; // pass -s and string
                    }
                }
                for (; j < argc; j++) { // process as files
                    g_ftssl_digest_op[i].ft_ssl_process(argv[j], ssl_mode, 1, g_ftssl_digest_op[i].name);
                    flag_process = 1;
                }
                if (flag_process == 0 || ssl_mode->std_mode == 1) // if no processed and std mode is activated
                    g_ftssl_digest_op[i].ft_ssl_process(NULL, ssl_mode, 2, g_ftssl_digest_op[i].name);
            }
        }

        for (int i = 0; i < op_des_size; i++) {
            if (ft_strcmp(argv[1], g_ftssl_des_op[i].name) == 0 && argc >= 2) {
                ft_search_modes(argv, argc, ssl_mode); // extract modes options
                flag = 1;
                int flag_key = 0;
                int should_read_stdin_pass = 0;
                int password_index = 0;
                char tmp_salt[17]; // 17 for \0


                for (int j = 2; j < argc; j++) {
                    if (ft_strcmp(argv[j], "-k") == 0 && flag_key == 0) { // process as key
                        if (argc < j + 1)
                        {
                            ft_putstr(ERROR_DES_KEY_NO_PROVIDED);
                            exit(0);  
                        }

                        // generate key and padd if the len of argv[j+1] is < 16
                        char tmp_key[17]; // 17 for \0
                        ssize_t result_hex = 0;
                        int len_key = ft_strlen(argv[j + 1]);

                        result_hex = gen_key_padding(argv[j + 1], tmp_key);

                        ssl_mode->key = result_hex;
                        j++;
                        flag_key = 1;
                    } else if (ft_strcmp(argv[j], "-o") == 0 && ssl_mode->output_fd == 0) { // process output file
                        if (argv[j + 1])
                        {
                            ssl_mode->output_fd = open(argv[j + 1], O_WRONLY | O_CREAT, 0777);
                            if (ssl_mode->output_fd == -1)
                            {
                                ft_putstr(ERROR_FILE);
                                ft_putstr(argv[j + 1]);
                                ft_putchar('\n');
                            }
                        } else {
                            ft_putstr(ERROR_OUTPUT_FILE_NOT_FOUND);
                            exit(1);
                        }
                        j++;
                    } else if (ft_strcmp(argv[j], "-i") == 0 && ssl_mode->output_fd == 0) { // process input file
                        if (argv[j + 1])
                        {
                            ssl_mode->input_fd = open(argv[j + 1], O_RDONLY);
                            if (ssl_mode->input_fd == -1)
                            {
                                ft_putstr(ERROR_FILE);
                                ft_putstr(argv[j + 1]);
                                ft_putchar('\n');
                            }
                        } else {
                            ft_putstr(ERROR_INPUT_FILE_NOT_FOUND);
                            exit(1);
                        }
                        j++;
                    } else if (ft_strcmp(argv[j], "-p") == 0) {
                        ssl_mode->have_password = 1;
                        if (!argv[j + 1])
                        {
                            // read in stdin
                            should_read_stdin_pass = 1;
                        } else {
                            // process as password
                            password_index = j + 1;
                        }
                    } else if (ft_strcmp(argv[j], "-s") == 0) {
                        if (argc > j + 1)
                        {
                            // generate salt and padd if the len of argv[j + 1] is < 16
                            ssize_t result_hex_salt = 0;
                            int len_key = ft_strlen(argv[j + 1]);
                            result_hex_salt = gen_key_padding(argv[j + 1], tmp_salt);
                            ssl_mode->have_salt = 1;
                        } else {
                            ft_putstr(ERROR_DES_SALT_NO_PROVIDED);
                            exit(0);
                        }
                        j++;
                    }
                }

                // if (ssl_mode->key == 0 && ft_strstr(argv[1], "des-ecb"))
                // {
                //     ft_putstr(ERROR_DES_KEY_NO_PROVIDED);
                //     exit(0);
                // }
                if (ssl_mode->key == 0)
                    ssl_mode->key = process_pbkdf(argv[password_index], (ssl_mode->have_salt == 1) ? tmp_salt : NULL, (ssl_mode->have_password == 0 || ssl_mode->have_salt == 0));

                ssl_mode->output_fd = (ssl_mode->output_fd == 0) ? 1 : ssl_mode->output_fd;
                g_ftssl_des_op[i].ft_ssl_process(argv[2], ssl_mode, 0, g_ftssl_digest_op[i].name);

                // TODO MAKE THESE LINE IN FUNCTION EXIT_MAIN_PROCESS
                if (ssl_mode->input_fd > 0)
                    close(ssl_mode->input_fd);
                if (ssl_mode->output_fd > 1)
                    close(ssl_mode->output_fd);
            }
        }
        if (flag == 0) { // error if digest algorithm not found
            ft_putstr(ERROR_ALGO_1);
            ft_putstr(argv[1]);
            ft_putstr(ERROR_ALGO_2);
            ft_putchar('\n');
        }
    } else {
        ft_putstr(USAGE);
    }
}