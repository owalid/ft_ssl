/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lst_pushback.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/13 15:42:26 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/13 17:59:32 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_lst_pushback(t_list **beginlst, t_list *lst)
{
	t_list	*push;

	push = ft_lstnew(lst->content, lst->content_size);
	while ((*beginlst)->next)
		beginlst = &(*beginlst)->next;
	(*beginlst)->next = push;
}
