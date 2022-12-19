/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/13 14:40:42 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 14:52:24 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int				ft_verif_base(int base)
{
	if (base >= 2 && base <= 16)
		return (1);
	return (0);
}

static int				get_second_nb(long long a)
{
	return (a % 10);
}

static int				nb_ofnb(long long nb, int base)
{
	int		i;

	i = 0;
	if (nb == 0)
		return (1);
	while (nb > 0)
	{
		nb /= base;
		i++;
	}
	return (i);
}

static void				is_neg(long long *nb, int *neg, int *size, int base)
{
	if (*nb < 0)
	{
		if (base == 10)
		{
			*neg = 1;
			*size += 1;
		}
		*nb *= -1;
	}
	*size += nb_ofnb(*nb, base) + 1;
}

char					*ft_itoa_base(int nb, int base)
{
	char				*result;
	long long			nb_long;
	int					size;
	int					neg;

	neg = 0;
	size = 0;
	nb_long = (long long)nb;
	if (!ft_verif_base(base))
		return (ft_strdup(""));
	is_neg(&nb_long, &neg, &size, base);
	if ((result = (char*)malloc(sizeof(char) * size)) == NULL)
		return (NULL);
	result[--size] = '\0';
	while (size--)
	{
		if (nb_long % base > 9)
			result[size] = 65 + get_second_nb(nb_long % base);
		else
			result[size] = nb_long % base + '0';
		nb_long /= base;
	}
	if (neg)
		result[0] = '-';
	return (result);
}
