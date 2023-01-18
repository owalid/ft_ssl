
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
# define ERROR_ALGO_2 " not found\n"
# define ERROR_ALGO_3 "ft_ssl -list to list all algorithm available"

# define ERROR_FILE "No such file or directory: "
# define ERROR_STR_OPT "Option -s should have an string as parameters."
# define ERROR_DES_NO_HEX "non-hex digit"
# define ERROR_DES_KEY_NO_PROVIDED "Key error: Key is required"
# define ERROR_DES_SALT_NO_PROVIDED "Salt error: Salt is required"
# define ERROR_DES_IV_NO_PROVIDED "IV error: Initial vector is required"
# define ERROR_DIR_READ "Read error in "
# define ERROR_OUTPUT_FILE_NOT_FOUND "Error output file"
# define ERROR_INPUT_FILE_NOT_FOUND "Error output file"
# define ERROR_READ_GLOBAL "Error on read"
# define ERROR_BASE64_BAD_INPUT "Error base64: invalid input"
# define ERROR_PASSWORD_REQUIRED "Password error: password is required with -p option"
// ---
// WARNING
// ---
# define WARNING_DES_KEY_TO_SHORT "Warning: hexa string too short, padding with zero bytes to length"
# define WARNING_DES_KEY_TO_LONG "Warning: hexa string too long, ignoring excess"
# define WARNING_IV_NOT_USED "Warning: iv not used by this cipher"

// ---
// OTHERS
// ---
# define USAGE "Usage: ft_ssl algorithm [options] [file...]\n\n\
Message Digest commands:\n\
md5, sha224, sha256, sha384, sha512.\n\n\
Cipher commands:\n\
base64, des, des-ecb, des-cbc\n\n\
Message Digest options:\n\
Output options: \n\
-r\treverse the format of the output.\n\
-p\techo STDIN to STDOUT and append the checksum to STDOUT.\n\
-q\tquiet mode.\n\
-s\tprint the sum of the given string.\n\
Parameters:\n\
file Files to digest (optional; default is stdin).\n\n\n\
Cipher options:\n\
-a\tdecode/encode the input/output in base64, depending on the encrypt mode.\n\
-d\tdecrypt mode.\n\
-e\tencrypt mode (default).\n\
-i\tinput file for message.\n\
-o\toutput file for message.\n\
-p\tpassword in ascii is the next argument.\n\
-s\tthe salt in hex is the next argument.\n\
-v\tinitialization vector in hex is the next argument.\n\n\
General options: \n\
-help\tDisplay this summary\n\
-list\tList digests\n"


# define ALGO_LIST "Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n\n\
Cipher commands:\n\
base64, des, des-ecb, des-cbc\n"

# define DGST_LIST "Message Digest algorithm:\n\
md5, sha256, sha224, sha384, sha512.\n"

# define CIPHER_LIST "Message Digest algorithm:\n\
base64, des, des-ecb, des-cbc\n"

typedef struct		s_ft_ssl_mode
{
	unsigned long	key;
	unsigned long	iv;	
	int				quiet_mode;
	int				reverse_mode;
	int				std_mode;
	int				input_fd;
	int				output_fd;
	int				decode_mode;
	int				encode_mode;
	int				have_password;
	int				have_salt;
	int				have_iv;
	int				have_key;
	int				des_b64;
	int				should_padd;
	int				counter;
}					t_ft_ssl_mode;

typedef 			void (*t_fn_process_firsts_blocks)(void *raw_w, void *raw_hash);
typedef				void (*t_fn_print_hash)(void *hash, size_t size);
typedef				unsigned long (*t_fn_encrypt_block)(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
typedef				unsigned long (*t_fn_decrypt_block)(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
typedef				void(*t_ft_ssl_basic_process)(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);


typedef struct		s_ft_ssl_digest_op
{
	char					*name;
	t_ft_ssl_basic_process	ft_ssl_dgst_process;
}					t_ft_ssl_digest_op;


typedef struct		s_ft_ssl_cipher_op
{
	char						*name;
	t_ft_ssl_basic_process		ft_ssl_cipher_process;
	t_fn_encrypt_block 			fn_encrypt_block;
	t_fn_decrypt_block 			fn_decrypt_block;
	short						should_have_key;
	short						should_have_iv;
	short						should_pad;
}					t_ft_ssl_cipher_op;



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
void 				simple_sha512(char *input, unsigned long *dest);


// === PBKDF ===

unsigned long    	process_pbkdf(char *pass, char *raw_salt, t_ft_ssl_mode *ssl_mode, int need_gen_iv);


// === DES ===

// base64.c
void    			base64_process(char *input, t_ft_ssl_mode *ssl_mode, int input_type, char *algo_name);
void 				three_bytes_to_b64(char *raw_input, ssize_t readed, int print, int fd);
ssize_t 			b64_to_three_bytes(char *raw_input, char *dest, ssize_t readed, int print, t_ft_ssl_mode *ssl_mode);

// des_ecb.c
unsigned long       encrypt_ecb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
unsigned long       decrypt_ecb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);

// des_ofb.c
unsigned long       encrypt_ofb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
unsigned long       decrypt_ofb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);

// des_cbc.c
unsigned long       encrypt_cbc_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
unsigned long       decrypt_cbc_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);

// des_cfb.c
unsigned long       encrypt_cfb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
unsigned long       decrypt_cfb_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);

// des_ctr.c
unsigned long       encrypt_ctr_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);
unsigned long       decrypt_ctr_block(unsigned long block, t_ft_ssl_mode *ssl_mode, unsigned long *round_key);



// === CIPHER PROCESS ===
void        		des_process(char *input, t_ft_ssl_mode *ssl_mode, t_fn_encrypt_block fn_encrypt_block, t_fn_decrypt_block fn_decrypt_block);
void        		des_decrypt_process(t_ft_ssl_mode *ssl_mode, unsigned long *r_k, t_fn_encrypt_block fn_encrypt_block);
void        		des_encrypt_process(t_ft_ssl_mode *ssl_mode, unsigned long *r_k, t_fn_encrypt_block fn_decrypt_block);
unsigned long* 		process_round_keys(unsigned long key, unsigned long *round_k);
unsigned long 		encrypt_block(unsigned long block, unsigned long *key);



// === DES UTILS ===

ssize_t     unpad(unsigned char *plain_block);
void        pad_block(unsigned char *input, ssize_t len_input);
void        display_key(unsigned long *r_k);
void        print_cipher_b64(unsigned long* blocks, int* len_block, int fd, int last_block_len);
// void        print_cipher_b64(unsigned long* blocks, int* len_block, int fd);
void    	print_cipher_raw(unsigned long* blocks, int *len_block, int fd, int len_last);
void        reverse_round_key(unsigned long *r_k);



// TODO REMOVE ONLY DEBUG

void 				print_bits(unsigned char *str, size_t len);
void print_bit(unsigned char n);

// utils.c
unsigned int        swap32(unsigned int num);
size_t              swap64(size_t val);
ssize_t 			utils_read(int fd, char *data, size_t size_block, t_ft_ssl_mode *ssl_mode);

unsigned int        left_rotate(unsigned int n, unsigned int d);

unsigned long       right_rotate_64(unsigned long n, unsigned long d);
unsigned int        right_rotate_32(unsigned int n, unsigned int d);

void				print_hash_32(void* hash, size_t size);
void 				print_hashes_64(void* hash, size_t size);
void 				print_hash_64(unsigned long hash, int lower);

void 				preprocess_final_output(t_ft_ssl_mode *ssl_mode, char *algo_name, int input_type, char *input, t_fn_print_hash fn_print_hash, void *hash, size_t size);
void    			print_errors(char *msg, t_ft_ssl_mode *ssl_mode);

// process.c
void				process_last_block(char *input, void *vars, size_t total_size, int should_swap, size_t byte_size, t_fn_process_firsts_blocks fn_process_firsts_blocks);
int 				fn_process(char *input, int input_type, size_t byte_size, void *vars, int should_swap, t_fn_process_firsts_blocks fn_process_firsts_blocks, t_ft_ssl_mode *ssl_mode, char *algo_name);

#endif
