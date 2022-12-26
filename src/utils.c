#include "ft_ssl.h"
#include "libft.h"
#include <fcntl.h>



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

void process_last_block(char *input, unsigned int *vars, size_t total_size, int should_swap, int byte_size, int treshold_bytes)
{
    size_t lasts_read = total_size % byte_size;
    
    if (lasts_read < byte_size) {
        ft_bzero(input + lasts_read + 1, byte_size - (lasts_read + 1));
    }

    if (lasts_read >= treshold_bytes) {
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
        ft_memcpy(tmp_input + treshold_bytes, &total_size, 8);
        md5_process_firsts_blocks((unsigned int*)input, vars);
        md5_process_firsts_blocks((unsigned int*)tmp_input, vars);
    } else {
        input[lasts_read] = 0x80;
        total_size *= 8;
        if (should_swap == 1)
            total_size = swap64(total_size);
        ft_memcpy(input + treshold_bytes, &total_size, 8);
        md5_process_firsts_blocks((unsigned int*)input, vars);
    }
}

void* fn_process(char *input, int input_type, int byte_size, int treshold_bytes, void *vars, t_fn_process_firsts_blocks fn_process_firsts_blocks)
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
        process_last_block(current_input, vars, size_of_input_copy, 0, byte_size, treshold_bytes);
        return vars;
        // printf("%08x%08x%08x%08x\n",__bswap_32(vars[0]), __bswap_32(vars[1]), __bswap_32(vars[2]), __bswap_32(vars[3]));
    } else if (input_type == 1 || input_type == 2) {
        int fd = (input_type == 2) ? 0 : open(input, O_RDONLY);

        if (fd > -1) {
            int readed = read(fd, current_input, byte_size);
            int total_size = readed;

            while (readed) {
                if (readed < byte_size) {
                    process_last_block(current_input, vars, total_size+readed, 0, byte_size, treshold_bytes);
                    return vars;
                    // printf("%08x%08x%08x%08x\n",__bswap_32(vars[0]), __bswap_32(vars[1]), __bswap_32(vars[2]), __bswap_32(vars[3]));
                    // break;
                } else {
                    fn_process_firsts_blocks(current_input, vars);
                    readed = read(fd, current_input, byte_size);
                    total_size += readed;
                }
            }
        }
    }
}