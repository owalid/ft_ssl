/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itohex.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/05/16 07:54:00 by oel-ayad          #+#    #+#             */
/*   Updated: 2022/12/26 20:59:48 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int				ft_verif_base(int base)
{
	if (base >= 2 && base <= 16)
		return (1);
	return (0);
}

static int				nb_ofnb(unsigned long long nb, int base)
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

char					*ft_utoa_base(unsigned long long n, int b)
{
	int			i;
	char		*result;

	i = nb_ofnb(n, b);
	if (!ft_verif_base(b) || !(result = ft_strnew(i)))
		return (NULL);
	while (i--)
	{
		if (n % b > 9)
			result[i] = n % b + 'A' - 10;
		else
			result[i] = n % b + '0';
		n /= b;
	}
	return (result);
}
