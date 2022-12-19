/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcapitalize.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/07 13:52:21 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/14 15:02:32 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

static int			ft_is_alpha_and_numeric(char *str, int i)
{
	if ((str[i] >= 'A' && str[i] <= 'Z') || (str[i] >= 'a' && str[i] <= 'z')
			|| (str[i] >= '0' && str[i] <= '9'))
		return (1);
	return (0);
}

char				*ft_strcapitalize(char *str)
{
	int		i;
	char	*result;

	i = 0;
	result = str;
	while (result[i] != '\0')
	{
		if (i == 0 || ft_is_alpha_and_numeric(result, i - 1) == 0)
		{
			if (result[i] >= 'a' && result[i] <= 'z')
				result[i] -= 32;
		}
		else if (result[i] >= 'A' && result[i] <= 'Z')
			result[i] += 32;
		i++;
	}
	return (result);
}
