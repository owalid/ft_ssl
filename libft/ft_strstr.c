/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/07 09:43:40 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 18:56:20 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

char		*ft_strstr(const char *str, const char *to_find)
{
	int i;
	int j;

	i = 0;
	if (!str[i] && !to_find[i])
		return ((char*)str);
	while (str[i])
	{
		j = 0;
		while (str[i + j] && to_find[j] && str[i + j] == to_find[j])
			j++;
		if (!to_find[j])
			return ((char*)(str + i));
		i++;
	}
	return (0);
}
