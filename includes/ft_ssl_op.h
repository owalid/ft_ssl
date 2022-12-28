
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
	{MD5, &md5_process},
	{SHA224, &sha224_process},
	{SHA256, &sha256_process},
    {SHA384, &sha384_process},
	{SHA512, &sha512_process},
};


# define DES_BASE64			"base64"

# define SIZE_DIGEST_OP    1

static t_ft_ssl_des_op 		g_ftssl_des_op[SIZE_DES_OP] =
{
	{BASE64, &base64_process}
}
#endif