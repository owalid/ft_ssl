/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/07 20:19:04 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 19:52:45 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncat(char *dest, const char *src, int nb)
{
	int		size;
	int		i;
	char	*result;

	i = 0;
	size = 0;
	result = dest;
	size = ft_strlen(result);
	i = 0;
	while (src[i] && i < nb)
	{
		result[size] = src[i];
		size++;
		i++;
	}
	result[size] = '\0';
	return (result);
}
