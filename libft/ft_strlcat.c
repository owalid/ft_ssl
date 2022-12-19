/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/08 17:21:30 by oel-ayad          #+#    #+#             */
/*   Updated: 2022/12/19 16:32:01 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t		size_dst;
	size_t		i;

	i = 0;
	size_dst = ft_strlen(dst);
	if (size < size_dst)
		return (ft_strlen(src) + size);
	while (src[i] && (size_dst + i) < (size - 1))
	{
		dst[size_dst + i] = src[i];
		i++;
	}
	dst[size_dst + i] = '\0';
	while (src[i])
		i++;
	return ((size_dst + i));
}
