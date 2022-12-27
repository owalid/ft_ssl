#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h>


void preprocess_final_output(t_ft_ssl_mode *ssl_mode, char *algo_name, int input_type, char *input, t_fn_print_hash fn_print_hash, void *hash, size_t size)
{
    if (ssl_mode->quiet_mode == 1)
        return;
    
    if (ssl_mode->reverse_mode == 0) {
        char *str_cpy = ft_strnew(ft_strlen(algo_name));
        ft_strcpy(str_cpy, algo_name);
        ft_putstr(ft_strupcase(str_cpy));
        free(str_cpy);
        if (input_type == 2) {
            ft_putstr(" (stdin)= ");
        } else if (input_type == 1) {
            ft_putstr(" (");
            ft_putstr(input);
            ft_putstr(")= ");
        } else {
            ft_putstr(" (\"");
            ft_putstr(input);
            ft_putstr("\")= ");
        }
        fn_print_hash(hash, size);
    } else {
        fn_print_hash(hash, size);
        if (input_type == 2) {
            ft_putstr(" *stdin");
        } else if (input_type == 1) {
            ft_putstr(" *");
            ft_putstr(input);
        } else {
            ft_putstr(" *\"");
            ft_putstr(input);
            ft_putchar('\"');
        }
    }
    ft_putchar('\n');
}

void print_hash_32(void *hash, size_t size)
{
    unsigned int *hashh = (unsigned int*)hash;
    char *str;
    int len;

    // PAS D'OPTIONS AFFICHER (ALGO)= HASH
    // OPTION -p AFFICHER ("STR")= HASH
    // OPTION -q AFFICHER HASH
    // FILE AFFICHER (FILE) HASH
    // OPTION -r AFFICHER HASH FILE ou HASH STR

    for (int i = 0; i < size; i++) {
        str = ft_strlowcase(ft_utoa_base(hashh[i], 16));
        len = ft_strlen(str);
        for (int i = 0; i < 8 - len; i++) {
            ft_putchar('0');
        }
        ft_putstr(str);
        free(str);
    }
}


void print_hash_64(void* hash, size_t size)
{
    char *str;
    int len;
    unsigned long *hashh = (unsigned long*)hash;

    for (int i = 0; i < size; i++) {
        str = ft_strlowcase(ft_utoa_base(hashh[i], 16));
        len = ft_strlen(str);
        for (int i = 0; i < 16 - len; i++) {
            ft_putchar('0');
        }
        ft_putstr(str);
        free(str);
    }
}

void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		printf("%d", (n >> i) & 1);
	}
	printf(" ");
}

void print_bits(unsigned char *str, size_t len) {
	for (size_t i = 0; i < len; i++) {
		print_bit(str[i]);
	}
    printf("\n\n");
}


unsigned int swap32(unsigned int num) {
    return ((num>>24)&0xff) | // move byte 3 to byte 0
        ((num<<8)&0xff0000) | // move byte 1 to byte 2
        ((num>>8)&0xff00) | // move byte 2 to byte 1
        ((num<<24)&0xff000000); // byte 0 to byte 3
}

size_t swap64(size_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
    return (val << 32) | (val >> 32);
}


unsigned long right_rotate_64(unsigned long n, unsigned long d) {
    return (n >> d) | (n << (64 - d));
}


unsigned int     left_rotate(unsigned int n, unsigned int d) {
    return (n << d)|(n >> (32 - d));
}



unsigned int right_rotate_32(unsigned int n, unsigned int d) {
    return (n >> d) | (n << (32 - d));
}

void process_last_block(char *input, void *vars, size_t total_size, int should_swap, int byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks)
{
    size_t lasts_read = total_size % byte_size;
    
    if (lasts_read < byte_size) {
        ft_bzero(input + lasts_read + 1, byte_size - (lasts_read + 1));
    }

    if (lasts_read >= (56*(byte_size/64))) {
        char tmp_input[byte_size];

        if (lasts_read >= byte_size) {
            tmp_input[byte_size] = 0x80;
        }
        else
            input[lasts_read] = 0x80;

        ft_bzero(tmp_input, byte_size);
        total_size *= 8;
        if (should_swap == 1)
            total_size = swap64(total_size);
        ft_memcpy(tmp_input + (byte_size-8), &total_size, 8);
        fn_process_firsts_blocks(input, vars);
        fn_process_firsts_blocks(tmp_input, vars);
    } else {
        input[lasts_read] = 0x80;
        total_size *= 8;
        if (should_swap == 1)
            total_size = swap64(total_size);
        ft_memcpy(input + (byte_size-8), &total_size, 8);
        fn_process_firsts_blocks(input, vars);
    }
}

void* fn_process(char *input, int input_type, int byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks)
{
    char current_input[byte_size];

    if (input_type == 0) {
        int size_of_input = ft_strlen(input);
        int size_of_input_copy = size_of_input;
        int size_cmpt = 0;

        if (ft_strlen(input) >= byte_size) {
            while (size_of_input >= byte_size) {
                ft_strncpy(current_input, input, byte_size);
                fn_process_firsts_blocks(current_input, vars);
                size_of_input -= byte_size;
                input += byte_size;
                size_cmpt += byte_size;
            } 
        }   

        ft_strncpy(current_input, input, byte_size);
        process_last_block(current_input, vars, size_of_input_copy, should_swap, byte_size, fn_process_firsts_blocks);
        return vars;
    }  else if (input_type == 1 || input_type == 2) { //TODO NEED TO CHANGE THIS
        int fd = (input_type == 2) ? 0 : open(input, O_RDONLY);
        printf("[FD]: %d", fd);
        if (fd > -1) {
            int readed = 0;
            int total_size = readed;
            char *tmp_input = ft_strnew(byte_size);

            while (readed = read(fd, current_input, byte_size)) {
                if ((total_size % byte_size) + readed >= byte_size) {
                    ft_memcpy((void *)tmp_input + (readed % byte_size), current_input, byte_size - (readed % byte_size));
                    fn_process_firsts_blocks((void *)tmp_input, vars);
                    ft_bzero((void *)tmp_input, byte_size);
                    ft_memcpy((void *)tmp_input, current_input + (total_size % byte_size), (total_size % byte_size));
                } else {
                    ft_memcpy((void *)tmp_input + (total_size % byte_size), current_input, readed);
                }
                total_size += readed;
            }
            process_last_block((void *)tmp_input, vars, total_size, should_swap, byte_size, fn_process_firsts_blocks);
            free(tmp_input);

            return vars;
        } else {
            ft_putstr(ERROR_FILE);
            return NULL;
        }
    }
}
