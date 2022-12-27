/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strupcase.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/12 21:29:12 by oel-ayad          #+#    #+#             */
/*   Updated: 2022/12/27 15:17:10 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_strupcase(char *str)
{
	int		i;

	i = -1;
	while (str[++i])
		if (ft_islower(str[i]))
			str[i] = ft_toupper(str[i]);
	return (str);
}
