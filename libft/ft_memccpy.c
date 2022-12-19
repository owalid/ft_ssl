/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/08 16:06:54 by oel-ayad          #+#    #+#             */
/*   Updated: 2022/12/19 16:30:01 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dest, const void *src, int c, size_t n)
{
	size_t	i;

	i = 0;
	while (n--)
	{
		((char*)dest)[i] = ((char*)src)[i];
		if (((char*)dest)[i] == (char)c)
			return (dest + i + 1);
		i++;
	}
	return (NULL);
}
