/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/09 13:20:26 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/15 20:21:23 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int			ft_is_separator(char c)
{
	if (c == ' ' || c == '\t' || c == '\n')
		return (1);
	return (0);
}

char				*ft_strtrim(char const *s)
{
	int		start;
	int		size;

	if (!s)
		return (NULL);
	if (!s[0])
		return (ft_strdup(""));
	start = 0;
	while (ft_is_separator(s[start]))
		start++;
	if (!s[start])
		return (ft_strdup(""));
	size = ft_strlen(s + start) - 1;
	while (ft_is_separator(s[size + start]) && size >= 0)
		size--;
	size++;
	return (ft_strsub(s, start, size));
}
