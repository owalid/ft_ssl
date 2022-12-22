
#ifndef FT_SSL_OP_H
# define FT_SSL_OP_H

# include "ft_ssl.h"

# define MD5		"md5"
# define SHA224		"sha224"
# define SHA256		"sha256"
# define SHA384     "sha384"
# define SHA512		"sha512"

# define SIZE_OP    5

static t_ft_ssl_op	g_ftssl_op[SIZE_OP] =
{
	{MD5, &md5_process},
	{SHA224, &sha224_process},
	{SHA256, &sha256_process},
    {SHA384, &sha384_process},
	{SHA512, &sha512_process},
};

#endif