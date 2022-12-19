/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstget_at.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 14:52:34 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 14:52:40 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstget_at(t_list *begin_list, size_t nb)
{
	t_list		*lst;
	size_t		i;

	i = 1;
	lst = begin_list;
	while (i < nb)
	{
		if (!lst)
			return (NULL);
		lst = lst->next;
		i++;
	}
	return (lst);
}
