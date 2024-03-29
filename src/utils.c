#include "ft_ssl.h"
#include "libft.h"

void    print_errors(char *msg, t_ft_ssl_mode *ssl_mode)
{
    ft_putstr_fd(msg, 2);
    ft_putchar('\n');

    if (ssl_mode)
    {
        if (ssl_mode->input_fd > 2)
            close(ssl_mode->input_fd);
        if (ssl_mode->output_fd > 2)
            close(ssl_mode->output_fd);
        exit(1);
    }
}

ssize_t delete_spaces(char *buffer, ssize_t len, int des_mode)
{
    ssize_t i = 0, offset = 0;
    char tmp_buffer[128];

    ft_bzero(tmp_buffer, 128);
    ft_memcpy(tmp_buffer, buffer, len);
    for (; i + offset < len; i++)
    {
        // delete all space for des mode
        // delete all space without ' ' for b64 mode
        while ((ft_isspace(tmp_buffer[i + offset]) && tmp_buffer[i + offset] != ' ')  || (tmp_buffer[i + offset] == ' ' && des_mode))
            offset++;
        tmp_buffer[i] = tmp_buffer[i + offset];
    }

    if (i + offset > len) i--;

    ft_strcpy(buffer, tmp_buffer);
    
    return i;
}

ssize_t utils_read(int fd, char *data, size_t size_block, t_ft_ssl_mode *ssl_mode) {
    unsigned char buffer[128];
    ssize_t len = 0;
    size_t size = 0;

    ft_bzero(data, size_block);
    while ((len = read(fd, buffer, size_block - size)) > 0) {
        if (ssl_mode->decode_mode && ssl_mode->des_b64) // remove \n and spaces
            len = delete_spaces((char*)buffer, len, ssl_mode->des_mode);

        ft_memcpy(data + size, buffer, len);
        size += len;
        if (size == size_block) {
            return size;
            size = 0;
        }
    }
    if (len < 0)
        return -1;

    return size;
}



void preprocess_final_output(t_ft_ssl_mode *ssl_mode, char *algo_name, int input_type, char *input, t_fn_print_hash fn_print_hash, void *hash, size_t size)
{
    int should_print_std = (input_type == 2 && ssl_mode->quiet_mode == 0 && ssl_mode->std_mode == 1) ? 1 : 0;
    
    if (should_print_std == 1 || ssl_mode->quiet_mode == 1) {
        fn_print_hash(hash, size);
        ft_putchar('\n');
        return;
    }
    
    if (ssl_mode->reverse_mode == 1) {
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
    } else {
        char *str_cpy = ft_strnew(ft_strlen(algo_name));
        ft_strcpy(str_cpy, algo_name);
        ft_putstr(ft_strupcase(str_cpy));
        free(str_cpy);
        if (input_type == 2) {
            ft_putstr("(stdin)= ");
        } else if (input_type == 1) {
            ft_putchar('(');
            ft_putstr(input);
            ft_putstr(")= ");
        } else {
            ft_putstr("(\"");
            ft_putstr(input);
            ft_putstr("\")= ");
        }
        fn_print_hash(hash, size);
    }
    ft_putchar('\n');
}

void print_hash_32(void *hash, size_t size)
{
    unsigned int *hashh = (unsigned int*)hash;
    char *str;
    int len;

    for (int i = 0; (size_t)i < size; i++) {
        str = ft_strlowcase(ft_utoa_base(hashh[i], 16));
        len = ft_strlen(str);
        for (int i = 0; i < 8 - len; i++)
            ft_putchar('0');
        ft_putstr(str);
        free(str);
    }
}

void print_hash_64(unsigned long hash, int lower, int should_swap, int fd)
{
    char *str;
    if (should_swap)
        hash = swap64(hash);

    if (lower)
        str = ft_strlowcase(ft_utoa_base(hash, 16));
    else
        str = ft_utoa_base(hash, 16);

    int len = ft_strlen(str);
    for (int i = 0; i < 16 - len; i++)
        ft_putchar_fd('0', fd);
    ft_putstr_fd(str, fd);
    free(str);
}

void print_hashes_64(void* hash, size_t size)
{
    unsigned long *hashh = (unsigned long*)hash;

    for (int i = 0; (size_t)i < size; i++) {
        print_hash_64(hashh[i], 1, 0, 1);
    }
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

unsigned int left_rotate(unsigned int n, unsigned int d) {
    return (n << d)|(n >> (32 - d));
}

unsigned int right_rotate_32(unsigned int n, unsigned int d) {
    return (n >> d) | (n << (32 - d));
}



void   read_salt(t_ft_ssl_mode *ssl_mode, char *tmp_salt)
{
    ssize_t len = 0;
    unsigned long salt;
    char buffer[72];
    char tmp_buffer[96];
    char *tmp_utoa;
    // process as 32
    /*
        96/4 = 24.0
        24*3 = 72
        72-16 = 56
        56 / 8 = 7.0
    */
    ft_bzero(buffer, 96);
    ft_bzero(tmp_buffer, 72);


    if (ssl_mode->des_b64)
    {
        len = utils_read(ssl_mode->input_fd, tmp_buffer, 96, ssl_mode);
        len = b64_to_three_bytes(tmp_buffer, buffer, len, 0, ssl_mode); // tmp_buffer 96 -> buffer 72

        // remove 2*8 firsts bytes
        ft_memcpy(&salt, buffer + 8, 8);

        // copy 8*4 last bytes
        ssl_mode->tmp_b64_buffer_read = len - 16;
        ft_memcpy(ssl_mode->tmp_b64_buffer, buffer + 16, ssl_mode->tmp_b64_buffer_read);
        ft_bzero(buffer + 8, 16);
    } else
        len = read(ssl_mode->input_fd, buffer, 8);

    if (len > 0)
    {
        if (ft_strcmp(buffer, "Salted__") == 0)
        {
            if (!ssl_mode->des_b64)
                len = read(ssl_mode->input_fd, &salt, 8);

            if (len < 0)
                print_errors(ERROR_READ_GLOBAL, ssl_mode);
            else if (len < 8)
                print_errors(ERROR_INCOMPLET_SALT, ssl_mode);
            else
                ssl_mode->salt_from_file += 16;

            salt = swap64(salt);
            tmp_utoa = ft_utoa_base(salt, 16);
            ft_memcpy(tmp_salt, tmp_utoa, 16);
            ssl_mode->have_salt = 1;
            free(tmp_utoa);
        } else {
            print_errors(ERROR_READ_GLOBAL, ssl_mode);
        }
    } else if (len < 0) {
        print_errors(ERROR_READ_GLOBAL, ssl_mode);
    }
}
