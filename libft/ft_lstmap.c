/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/09 16:44:29 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 16:22:42 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list				*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list		*result;

	result = ft_lstnew(f(lst)->content, f(lst)->content_size);
	lst = lst->next;
	while (lst)
	{
		ft_lst_pushback(&result, f(lst));
		lst = lst->next;
	}
	return (result);
}
