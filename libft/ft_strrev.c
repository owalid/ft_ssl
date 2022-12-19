/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrev.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/14 14:54:11 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 15:02:17 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

static void		ft_swap_char(char *a, char *b)
{
	char temp;

	temp = *a;
	*a = *b;
	*b = temp;
}

char			*ft_strrev(char *str)
{
	char	*result;
	int		i;
	int		len;

	i = 0;
	len = 0;
	result = str;
	while (result[len])
	{
		len++;
	}
	while (i < (len / 2))
	{
		ft_swap_char(result + i, result + len - i - 1);
		i++;
	}
	return (result);
}
