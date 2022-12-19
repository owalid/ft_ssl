/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/09 15:36:07 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/15 17:21:35 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstnew(void const *content, size_t content_size)
{
	t_list	*result;

	if ((result = (t_list*)malloc(sizeof(t_list))) == NULL)
		return (NULL);
	if (!content || !content_size)
	{
		result->content = NULL;
		result->content_size = 0;
	}
	else
	{
		result->content = ft_memalloc(content_size);
		if (!result->content)
		{
			free(result);
			return (NULL);
		}
		ft_memcpy(result->content, content, content_size);
		result->content_size = content_size;
	}
	result->next = NULL;
	return (result);
}
