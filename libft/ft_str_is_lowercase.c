/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_str_is_lowercase.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 19:01:31 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/13 14:38:49 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int			ft_str_is_lowercase(const char *str)
{
	int		i;

	i = -1;
	while (str[++i])
		if (!(ft_islower(str[i])))
			return (0);
	return (1);
}
