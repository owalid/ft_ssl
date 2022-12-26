
#ifndef FTSSL_H
# define FTSSL_H

# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <stdio.h>


typedef struct		s_ft_ssl_mode
{
	int			quiet_mode;
	int			reverse_mode;
	int			std_mode;
}					t_ft_ssl_mode;

typedef 			void (*t_fn_process_firsts_blocks)(void *w, void *vars);

void                md5_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type);
void    			md5_process_firsts_blocks(void *w, void *vars);

void                sha224_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type);

void                sha256_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type);
void    			sha256_process_firsts_blocks(void *w, void *vars);

void                sha384_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type);

void                sha512_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type);
void    			sha512_process_firsts_blocks(void *w, void *vars);

void                print_bits(unsigned char *str, size_t len);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        swap32(unsigned int num);
size_t              swap64(size_t val);
unsigned long       right_rotate_64(unsigned long n, unsigned long d);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        right_rotate_32(unsigned int n, unsigned int d);
void				print_hash_32(unsigned int *hash, size_t size);
void				print_hash_64(unsigned long *hash, size_t size);


void				process_last_block(char *input, void *vars, size_t total_size, int should_swap, int byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks);
void* 				fn_process(char *input, int input_type, int byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks);


typedef struct		s_ft_ssl_op
{
	char		*name;
	void		(*ft_ssl_process)(char *input, t_ft_ssl_mode *ssl_mode, int input_type);
}					t_ft_ssl_op;



#endif
