/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strntolower.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 19:38:40 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/12 21:35:07 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_strnlowcase(char *str, size_t n)
{
	size_t		i;

	i = 0;
	while (str[i] && i < n)
	{
		str[i] = ft_tolower(str[i]);
		i++;
	}
	return (str);
}
