/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstfind.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 14:52:51 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 14:52:54 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstfind(t_list *begin_list, void *data)
{
	if (!begin_list)
		return (NULL);
	while (begin_list)
	{
		if (ft_memcmp(begin_list->content, data, begin_list->content_size) == 0)
			return (begin_list);
		begin_list = begin_list->next;
	}
	return (NULL);
}
