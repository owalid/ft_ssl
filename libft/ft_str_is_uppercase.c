/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_is_uppercase.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 19:16:15 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/12 19:18:34 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_str_is_uppercase(const char *str)
{
	int		i;

	i = -1;
	while (str[++i])
		if (!(ft_isupper(str[i])))
			return (0);
	return (1);
}
