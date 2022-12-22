
#ifndef FTSSL_H
# define FTSSL_H

# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <stdio.h>


void                md5_process(char *input);
void                md5_process_firsts_blocks(unsigned int *w, unsigned int *vars);
void                md5_process_last_block(char *input, unsigned int *vars);

void                sha256_process(char *input);
void                sha256_process_firsts_blocks(unsigned int *w, unsigned int *vars);
void                sha256_process_last_block(char *input, unsigned int *vars);

void                sha512_process(char *input);
void                sha512_process_firsts_blocks(unsigned long *w, unsigned long *vars);
void                sha512_process_last_block(char *input, unsigned long *vars);


void                sha384_process(char *input);
void                sha384_process_firsts_blocks(unsigned int *w, unsigned long *vars);
void                sha384_process_last_block(char *input, unsigned long *vars);

void                print_bits(unsigned char *str, size_t len);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        swap32(unsigned int num);
size_t              swap64(size_t val);
unsigned long       right_rotate_512(unsigned long n, unsigned long d);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        right_rotate_256(unsigned int n, unsigned int d);
unsigned int        left_rotate(unsigned int n, unsigned int d);
unsigned int        right_rotate_256(unsigned int n, unsigned int d);

typedef struct		s_ft_ssl_op
{
	char		*name;
	void		(*ft_ssl_process)(char *input);
}					t_ft_ssl_op;

#endif
