# include "ft_ssl.h"
# include "libft.h"

void process_last_block(char *input, void *vars, size_t total_size, int should_swap, size_t byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks)
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

int fn_process(char *input, int input_type, size_t byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks, t_ft_ssl_mode *ssl_mode, char *algo_name)
{
    char current_input[128];
    ft_bzero((void *)current_input, 128);

    if (input_type == 0) { // string
        int size_of_input = ft_strlen(input);
        int size_of_input_copy = size_of_input;
        int size_cmpt = 0;

        if (ft_strlen(input) >= byte_size) {
            while ((size_t)size_of_input >= byte_size) {
                ft_strncpy(current_input, input, byte_size);
                fn_process_firsts_blocks(current_input, vars);
                size_of_input -= byte_size;
                input += byte_size;
                size_cmpt += byte_size;
            } 
        }   

        ft_strncpy(current_input, input, byte_size);
        process_last_block(current_input, vars, size_of_input_copy, should_swap, byte_size, fn_process_firsts_blocks);
        return 1;
    }  else if (input_type == 1 || input_type == 2) { // 1 => file; 2 => stdin
        int should_print_std = (input_type == 2 && ssl_mode->std_mode == 1) ? 1 : 0;
        
        if (should_print_std == 1 && ssl_mode->quiet_mode == 0) {
            char *str_cpy = ft_strnew(ft_strlen(algo_name));
            ft_strcpy(str_cpy, algo_name);
            ft_putstr(ft_strupcase(str_cpy));
            free(str_cpy);
            ft_putstr("(\"");
        }

        int fd = (input_type == 2) ? 0 : open(input, O_RDONLY);
        if (fd > -1) {
            int readed = 0;
            int total_size = readed;
            char tmp_input[128];
            ft_bzero((void *)tmp_input, 128);

            while ((readed = read(fd, current_input, byte_size)) > 0) {
                if (should_print_std == 1)
                    ft_putstr(current_input);
                if ((total_size % byte_size) + readed >= byte_size) {
                    ft_memcpy((void *)tmp_input + (readed % byte_size), current_input, byte_size - (readed % byte_size));
                    fn_process_firsts_blocks((void *)tmp_input, vars);
                    ft_bzero((void *)tmp_input, byte_size);
                    ft_memcpy((void *)tmp_input, current_input + (total_size % byte_size), (total_size % byte_size));
                } else
                    ft_memcpy((void *)tmp_input + (total_size % byte_size), current_input, readed);
                total_size += readed;
            }

            ft_bzero((void *)current_input, byte_size);
            process_last_block((void *)tmp_input, vars, total_size, should_swap, byte_size, fn_process_firsts_blocks);
            
            if (should_print_std == 1) {
                if (ssl_mode->quiet_mode == 0)
                    ft_putstr("\")= ");
                else
                    ft_putchar('\n');
            }
            return 1;
        } else {
            ft_putstr(ERROR_FILE);
            ft_putstr(input);
            ft_putchar('\n');
            return 0;
        }
    }
    return 0;
}