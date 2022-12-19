/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/08 16:54:57 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/09 19:48:20 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strchr(char *str, int c)
{
	int		i;

	i = -1;
	while (str[++i])
		if (str[i] == (unsigned char)c)
			return (&str[i]);
	if (!c)
		return (&str[i]);
	return (NULL);
}
