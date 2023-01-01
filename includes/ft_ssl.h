
#ifndef FTSSL_H
# define FTSSL_H

# include <fcntl.h>
# include <stdio.h>

# define ERROR_FILE "No such file or directory: "
# define ERROR_ALGO_1 "Error algorithm "
# define ERROR_ALGO_2 " not found"
# define USAGE "Usage: ft_ssl algorithm [options] [file...]\n\n\
Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n\n\
General options: \n\
-help Display this summary\n\
-list List digests\n\n\
Output options: \n\
-r reverse the format of the output.\n\
-p echo STDIN to STDOUT and append the checksum to STDOUT.\n\
-q quiet mode.\n\
-s print the sum of the given string.\n\n\
Parameters:\n\
file Files to digest (optional; default is stdin).\n"

# define ERROR_STR_OPT "Option -s should have an string as parameters.\n"

# define ALGO_LIST "Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n"


typedef struct		s_ft_ssl_mode
{
	int			quiet_mode;
	int			reverse_mode;
	int			std_mode;
}					t_ft_ssl_mode;

typedef struct      s_ft_ssl_ctx
{
    char            *algo_name;
    char            *input;
    int             input_type;
    size_t          byte_size;
    int             should_swap;
    t_ft_ssl_mode   *ssl_mode;
}                   t_ft_ssl_ctx;

typedef struct		s_ft_ssl_op
{
	char		*name;
	void		(*ft_ssl_process)(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
}					t_ft_ssl_op;


typedef 			void (*t_fn_process_firsts_blocks)(void *raw_w, void *raw_hash);
typedef				void (*t_fn_print_hash)(void *hash, size_t size);

// md5.c
void   				md5_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
void    			md5_process_firsts_blocks(void *raw_w, void *raw_hash);

// sha224.c
void    			sha224_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);

// sha256.c
void    			sha256_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
void    			sha256_process_firsts_blocks(void *raw_w, void *raw_hash);

// sha384.c
void    			sha384_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);

// sha512.c
void    			sha512_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
void    			sha512_process_firsts_blocks(void *raw_w, void *raw_hash);

// utils.c
unsigned int        swap32(unsigned int num);
size_t              swap64(size_t val);

unsigned int        left_rotate(unsigned int n, unsigned int d);

unsigned long       right_rotate_64(unsigned long n, unsigned long d);
unsigned int        right_rotate_32(unsigned int n, unsigned int d);

void				print_hash_32(void* hash, size_t size);
void 				print_hash_64(void* hash, size_t size);

void 				preprocess_final_output(t_ft_ssl_mode *ssl_mode, char *algo_name, int input_type, char *input, t_fn_print_hash fn_print_hash, void *hash, size_t size);

// process.c
void				process_last_block(char *input, void *vars, size_t total_size, int should_swap, size_t byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks);
int 				fn_process(char *input, int input_type, size_t byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks, t_ft_ssl_mode *ssl_mode, char *algo_name);

#endif
