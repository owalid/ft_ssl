#include "ft_ssl.h"
#include "libft.h"


void print_bit(unsigned char n) {
	for (int i = 7; i >= 0; i--) {
		printf("%d", (n >> i) & 1);
	}
	printf(" ");
}

void print_bits(unsigned char *str, size_t len) {
	for (size_t i = 0; i < len; i++) {
		if (!(i % 8)) printf("\n");
		print_bit(str[i]);
	}
	printf("\n");
}

ssize_t delete_spaces(char *buffer, ssize_t len)
{
    for (int i = 0; i < len; i++)
    {
        if (ft_isspace(buffer[i]) == 1)
        {
            buffer[i] = buffer[i + 1];
            i--;
            len--;
        }
    }
    return len;
}

ssize_t utils_read(int fd, char *data, size_t size_block, int decode_mode) {
    unsigned char buffer[128];
    ssize_t len = 0;
    size_t size = 0;

    ft_bzero(data, size_block);
    while ((len = read(fd, buffer, size_block - size)) > 0) {
        if (decode_mode) // remove \n and spaces
            len = delete_spaces(buffer, len);
        ft_memcpy(data + size, buffer, len);
        size += len;
        if (size == size_block) {
            return size;
        }
    }
    if (len < 0) {
        return -1;
    }
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

void print_hash_64(unsigned long hash, int lower)
{
    char *str;
    if (lower)
        str = ft_strlowcase(ft_utoa_base(hash, 16));
    else
        str = ft_utoa_base(hash, 16);

    int len = ft_strlen(str);
    for (int i = 0; i < 16 - len; i++)
        ft_putchar('0');
    ft_putstr(str);
    free(str);
}

void print_hashes_64(void* hash, size_t size)
{
    char *str;
    int len;
    unsigned long *hashh = (unsigned long*)hash;

    for (int i = 0; (size_t)i < size; i++) {
        print_hash_64(hashh[i], 1);
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
