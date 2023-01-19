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
                    || ft_strcmp(argv[i], "-o") == 0 || ft_strcmp(argv[i], "-k") == 0
                    || ft_strcmp(argv[i], "-v") == 0) { // need to be process after
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

unsigned long gen_key_padding(char *raw_k, char *dest_key, t_ft_ssl_mode *ssl_mode)
{
    // Padding key to 16 bytes if needed
    // return key in hex
    ssize_t result_hex = 0;
    int len_key = ft_strlen(raw_k);
    ft_bzero(dest_key, 17);
    ft_memset(dest_key, '0', 16);
    ft_memcpy(dest_key, raw_k, (len_key > 16) ? 16 : len_key); // ignoring excess after len 16

    result_hex = ft_hextol(dest_key);

    if (result_hex == -1 || len_key < 0) print_errors(ERROR_DES_NO_HEX, ssl_mode);
    else if (len_key < 16) {
        ft_putstr_fd(WARNING_DES_KEY_TO_SHORT, 2);
        ft_putchar_fd('\n', 2);
    }
    else if (len_key > 16) {
        ft_putstr_fd(WARNING_DES_KEY_TO_LONG, 2);
        ft_putchar_fd('\n', 2);
    }

    return result_hex;
}

int main(int argc, char **argv) {
    int flag = 0;
    int s_flag = 0; // check if we have already an -s options
    int op_dig_size = sizeof(g_ftssl_digest_op) / sizeof(g_ftssl_digest_op[0]); // get size of array of digest algorithms
    int op_des_size = sizeof(g_ftssl_des_op) / sizeof(g_ftssl_des_op[0]); // get size of array of ciphers algorithms

    t_ft_ssl_mode ssl_mode[1];
    ft_bzero(&ssl_mode, sizeof(t_ft_ssl_mode));

    if (argc == 3 || argc == 2) { // display -list and -help options
        if ((argc == 2 && ft_strcmp(argv[1], "-list") == 0) || (argc == 3 && ft_strcmp(argv[2], "-list") == 0)) {
            ft_putstr(ALGO_LIST);
            exit(0);
        } else if (ft_strcmp(argv[1], "-help") == 0 || (argc == 3 && ft_strcmp(argv[2], "-help") == 0)) {
            ft_putstr(USAGE);
            exit(0);
        } else if ((argc == 2 && ft_strcmp(argv[1], "-dgst") == 0) || (argc == 3 && ft_strcmp(argv[2], "-dgst") == 0)) {
            ft_putstr(DGST_LIST);
            exit(0);
        } else if ((argc == 2 && ft_strcmp(argv[1], "-cipher") == 0) || (argc == 3 && ft_strcmp(argv[2], "-cipher") == 0)) {
            ft_putstr(CIPHER_LIST);
            exit(0);
        }
    }
    if (argc >= 2) {

        // ---
        // digest processing
        // ---
        for (int i = 0; i < op_dig_size; i++) {
            if (ft_strcmp(argv[1], g_ftssl_digest_op[i].name) == 0) { // get name of digest algorithm
                flag = 1;
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
                        if (argc < (j + 1) || !argv[j+1])
                            print_errors(ERROR_STR_OPT, ssl_mode);
                        if (s_flag == 0) {
                            g_ftssl_digest_op[i].ft_ssl_dgst_process(argv[j + 1], ssl_mode, 0, g_ftssl_digest_op[i].name);
                            flag_process = 1;
                            s_flag = 1;
                        }
                        j++; // pass -s and string
                    }
                }
                for (; j < argc; j++) { // process as files
                    g_ftssl_digest_op[i].ft_ssl_dgst_process(argv[j], ssl_mode, 1, g_ftssl_digest_op[i].name);
                    flag_process = 1;
                }
                if (flag_process == 0 || ssl_mode->std_mode == 1) // if no processed and std mode is activated
                    g_ftssl_digest_op[i].ft_ssl_dgst_process(NULL, ssl_mode, 2, g_ftssl_digest_op[i].name);
            }
        }


        // ---
        // ciphers processing
        // ---
        for (int i = 0; i < op_des_size; i++) {
            if (ft_strcmp(argv[1], g_ftssl_des_op[i].name) == 0 && argc >= 2) {
                ft_search_modes(argv, argc, ssl_mode); // extract modes options
                flag = 1;
                int flag_key = 0;
                int should_read_stdin_pass = 1;
                int password_index = 0;
                char tmp_salt[17]; // 17 for \0
                char tmp_iv[17]; // 17 for \0
                char tmp_key[17]; // 17 for \0


                for (int j = 2; j < argc; j++) {
                    if (ft_strcmp(argv[j], "-k") == 0 && flag_key == 0) { // process as key
                        if (argc < j + 1)
                            print_errors(ERROR_DES_KEY_NO_PROVIDED, ssl_mode);

                        // generate key and padd if the len of argv[j+1] is < 16
                        ssize_t result_hex = 0;
                        int len_key = ft_strlen(argv[j + 1]);
                        result_hex = gen_key_padding(argv[j + 1], tmp_key, ssl_mode);
                        ssl_mode->key = result_hex;
                        ssl_mode->have_key = 1;
                        j++;
                        flag_key = 1;
                    } else if (ft_strcmp(argv[j], "-o") == 0 && ssl_mode->output_fd == 0) { // process output file
                        if (argv[j + 1])
                        {
                            ssl_mode->output_fd = open(argv[j + 1], O_WRONLY | O_CREAT, 0777);
                            if (ssl_mode->output_fd == -1)
                            {
                                ft_putstr_fd(ERROR_FILE, 2);
                                print_errors(argv[j + 1], ssl_mode);
                            }
                        } else
                            print_errors(ERROR_OUTPUT_FILE_NOT_FOUND, ssl_mode);
                        j++;
                    } else if (ft_strcmp(argv[j], "-i") == 0 && ssl_mode->output_fd == 0) { // process input file
                        if (argv[j + 1])
                        {
                            ssl_mode->input_fd = open(argv[j + 1], O_RDONLY);
                            if (ssl_mode->input_fd == -1)
                            {   
                                ft_putstr_fd(ERROR_FILE, 2);
                                print_errors(argv[j + 1], ssl_mode);
                            }
                        } else
                            print_errors(ERROR_INPUT_FILE_NOT_FOUND, ssl_mode);
                        j++;
                    } else if (ft_strcmp(argv[j], "-p") == 0) { // process as password
                        ssl_mode->have_password = 1;
                        should_read_stdin_pass = 1;
                        password_index = j + 1;
                        if (!argv[j + 1])
                            print_errors(ERROR_PASSWORD_REQUIRED, ssl_mode);
                        j++;
                    } else if (ft_strcmp(argv[j], "-s") == 0) { // process as salt
                        if (argc > j + 1)
                        {
                            // generate salt and padd if the len of argv[j + 1] is < 16
                            ssize_t result_hex_salt = 0;
                            int len_key = ft_strlen(argv[j + 1]);
                            result_hex_salt = gen_key_padding(argv[j + 1], tmp_salt, ssl_mode);
                            ssl_mode->have_salt = 1;
                        }
                        else // if we don't have salt, initialize with 0
                        {
                            ft_memset(tmp_salt, '0', 16);
                            tmp_salt[16] = 0;
                        }
                        j++;
                    } else if (ft_strcmp(argv[j], "-v") == 0) { // process as iv
                        ssl_mode->have_iv = 1;
                        if (!argv[j + 1] || argc < j + 1)
                        {
                            ft_memset(tmp_iv, '0', 16);
                            tmp_iv[16] = 0;
                        }
                        else // generate iv and padd if the len of argv[j + 1] is < 16
                            ssl_mode->iv = gen_key_padding(argv[j + 1], tmp_iv, ssl_mode);
                        j++;
                    }
                }

                // process password generation with pkdf
                if (g_ftssl_des_op[i].should_have_key)
                {
                    if (ssl_mode->have_key && g_ftssl_des_op[i].should_have_iv && !ssl_mode->have_iv) // if have key and we don't have iv return error like openssl
                            print_errors(ERROR_DES_IV_NO_PROVIDED, ssl_mode);
                    
                    if (!ssl_mode->have_key) // if we don't have key and we should have key, use pbkdf
                        process_pbkdf(argv[password_index], (ssl_mode->have_salt == 1) ? tmp_salt : NULL, ssl_mode, g_ftssl_des_op[i].should_have_iv);
                }
                
                if (ssl_mode->iv != 0 && !g_ftssl_des_op[i].should_have_iv)
                {
                    ft_putstr_fd(WARNING_IV_NOT_USED, 2);
                    ft_putchar_fd('\n', 2);
                }
                
                ssl_mode->should_padd = g_ftssl_des_op[i].should_pad; // for des-ofb, des-cfb, des-ctr

                if (ft_strcmp(argv[1], "base64") == 0)
                    ssl_mode->des_b64 = 1;

                ssl_mode->iv = swap64(ssl_mode->iv);
                ssl_mode->output_fd = (ssl_mode->output_fd == 0) ? 1 : ssl_mode->output_fd;

                // DES and base64 have different process so we need to check if the function is available
                if (g_ftssl_des_op[i].ft_ssl_cipher_process) // for base64
                    g_ftssl_des_op[i].ft_ssl_cipher_process(argv[2], ssl_mode, 0, g_ftssl_des_op[i].name);
                else if (g_ftssl_des_op[i].fn_encrypt_block && g_ftssl_des_op[i].fn_decrypt_block) // for all des-*
                    des_process(argv[2], ssl_mode, g_ftssl_des_op[i].fn_encrypt_block, g_ftssl_des_op[i].fn_decrypt_block);
                else
                    print_errors("Unexcepted error", ssl_mode);

                // close file descriptors properly
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
            ft_putstr(ERROR_ALGO_3);
            ft_putchar('\n');
        }
    } else {
        ft_putstr(USAGE);
    }
}