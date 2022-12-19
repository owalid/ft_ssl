/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/08 17:01:42 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/09 19:53:11 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_strrchr(const char *s, int c)
{
	int		i;
	int		find;

	find = -1;
	i = -1;
	if (!c)
		return (&((char*)s)[ft_strlen(s)]);
	while (s[++i])
		if (s[i] == c)
			find = i;
	if (find != -1)
		return (&((char*)s)[find]);
	return (NULL);
}
