
#ifndef FTSSL_H
# define FTSSL_H

# include <fcntl.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>

// ---
// ERRORS
// ---

# define ERROR_ALGO_1 "Error algorithm "
# define ERROR_ALGO_2 " not found"

# define ERROR_FILE "No such file or directory: "
# define ERROR_STR_OPT "Option -s should have an string as parameters.\n"
# define ERROR_DES_NO_HEX "non-hex digit"
# define ERROR_DES_KEY_NO_PROVIDED "Key error: Key is required"
# define ERROR_DES_SALT_NO_PROVIDED "Salt error: Salt is required"
# define ERROR_DES_IV_NO_PROVIDED "IV error: Initial vector is required"
# define ERROR_DIR_READ "Read error in "
# define ERROR_OUTPUT_FILE_NOT_FOUND "Error output file"
# define ERROR_INPUT_FILE_NOT_FOUND "Error output file"
# define ERROR_READ_GLOBAL "Error on read"

// ---
// WARNING
// ---
# define WARNING_DES_KEY_TO_SHORT "Warning: hexa string too short, padding with zero bytes to length\n"
# define WARNING_DES_KEY_TO_LONG "Warning: hexa string too long, ignoring excess\n"

// ---
// OTHERS
// ---
# define USAGE "Usage: ft_ssl algorithm [options] [file...]\n\n\
Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n\n\
Cipher commands:\n\
base64, des, des-ecb, des-cbc\n\n\
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


# define ALGO_LIST "Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n"


typedef struct		s_ft_ssl_mode
{
	int				quiet_mode;
	int				reverse_mode;
	int				std_mode;
	int				input_fd;
	int				output_fd;
	int				decode_mode;
	int				encode_mode;
	unsigned long	key;
	int				have_password;
	int				have_salt;
	unsigned long	iv;
	int				des_b64;
}					t_ft_ssl_mode;

typedef struct		s_ft_ssl_op
{
	char		*name;
	void		(*ft_ssl_process)(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
}					t_ft_ssl_op;


typedef 			void (*t_fn_process_firsts_blocks)(void *raw_w, void *raw_hash);
typedef				void (*t_fn_print_hash)(void *hash, size_t size);


//  === DIGEST ===

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
unsigned long 		simple_sha512(char *input);


// === PBKDF ===

unsigned long    	process_pbkdf(char *pass, char *raw_salt, int stdin_mode);


// === DES ===

// base64.c
void    			base64_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
void 				three_bytes_to_b64(char *raw_input, ssize_t readed, int print, int fd);
ssize_t 			b64_to_three_bytes(char *raw_input, char *dest, ssize_t readed, int print, int fd);

// des_ecb.c
void    			des_ecb_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);


// des_cbc.c
void        		des_cbc_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);

// TODO REMOVE ONLY DEBUG

void 				print_bits(unsigned char *str, size_t len);
void print_bit(unsigned char n);

// utils.c
unsigned int        swap32(unsigned int num);
size_t              swap64(size_t val);
ssize_t 			utils_read(int fd, char *data, size_t size_block, int decode_mode);

unsigned int        left_rotate(unsigned int n, unsigned int d);

unsigned long       right_rotate_64(unsigned long n, unsigned long d);
unsigned int        right_rotate_32(unsigned int n, unsigned int d);

void				print_hash_32(void* hash, size_t size);
void 				print_hashes_64(void* hash, size_t size);
void 				print_hash_64(unsigned long hash, int lower);

void 				preprocess_final_output(t_ft_ssl_mode *ssl_mode, char *algo_name, int input_type, char *input, t_fn_print_hash fn_print_hash, void *hash, size_t size);

// process.c
void				process_last_block(char *input, void *vars, size_t total_size, int should_swap, size_t byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks);
int 				fn_process(char *input, int input_type, size_t byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks, t_ft_ssl_mode *ssl_mode, char *algo_name);

#endif
