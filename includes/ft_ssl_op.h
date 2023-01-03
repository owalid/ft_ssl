
#ifndef FT_SSL_OP_H
# define FT_SSL_OP_H

# include "ft_ssl.h"

# define DIGEST_MD5			"md5"
# define DIGEST_SHA224		"sha224"
# define DIGEST_SHA256		"sha256"
# define DIGEST_SHA384     	"sha384"
# define DIGEST_SHA512		"sha512"

static t_ft_ssl_op	g_ftssl_digest_op[] =
{
	{DIGEST_MD5, &md5_process},
	{DIGEST_SHA224, &sha224_process},
	{DIGEST_SHA256, &sha256_process},
    {DIGEST_SHA384, &sha384_process},
	{DIGEST_SHA512, &sha512_process}
};


# define DES_BASE64			"base64"
# define DES_ECB			"des-ecb"

static t_ft_ssl_op 		g_ftssl_des_op[] =
{
	{DES_BASE64, &base64_process},
	{DES_ECB, &des_ecb_process},
};

#endif