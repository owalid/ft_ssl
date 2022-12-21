
#ifndef FTSSL_H
# define FTSSL_H

# include <unistd.h>
# include <stdlib.h>
# include <string.h>
# include <stdio.h>


void     md5_process(char *input);
void    md5_process_firsts_blocks(unsigned int *w, unsigned int *vars);
void    md5_process_last_block(char *input, unsigned int *vars);
unsigned int     left_rotate(unsigned int n, unsigned int d);
void print_bits(unsigned char *str, size_t len);
#endif
