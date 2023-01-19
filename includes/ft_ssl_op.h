
#ifndef FT_SSL_OP_H
# define FT_SSL_OP_H

# include "ft_ssl.h"

# define DIGEST_MD5			"md5"
# define DIGEST_SHA224		"sha224"
# define DIGEST_SHA256		"sha256"
# define DIGEST_SHA384     	"sha384"
# define DIGEST_SHA512		"sha512"

static t_ft_ssl_digest_op	g_ftssl_digest_op[] =
{
	{DIGEST_MD5, &md5_process},
	{DIGEST_SHA224, &sha224_process},
	{DIGEST_SHA256, &sha256_process},
    {DIGEST_SHA384, &sha384_process},
	{DIGEST_SHA512, &sha512_process}
};


# define DES_BASE64			"base64"
# define DES_ECB			"des-ecb"
# define DES				"des"
# define DES_CBC			"des-cbc"
# define DES_OFB			"des-ofb"
# define DES_CFB			"des-cfb"
# define DES_CTR			"des-ctr"

static t_ft_ssl_cipher_op 		g_ftssl_des_op[] =
{
	{DES_BASE64, &base64_process, NULL, NULL, 0, 0, 1},
	{DES_ECB, NULL, &encrypt_ecb_block, &decrypt_ecb_block, 1, 0, 1},
	{DES, NULL, &encrypt_cbc_block, &decrypt_cbc_block, 1, 1, 1},
	{DES_CBC, NULL, &encrypt_cbc_block, &decrypt_cbc_block, 1, 1, 1},
	{DES_OFB, NULL, &encrypt_ofb_block, &decrypt_ofb_block, 1, 1, 0},
	{DES_CFB, NULL, &encrypt_cfb_block, &decrypt_cfb_block, 1, 1, 0},
	{DES_CTR, NULL, &encrypt_ctr_block, &decrypt_ctr_block, 1, 1, 0},
};

#endif