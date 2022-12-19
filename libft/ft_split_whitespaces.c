/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split_whitespaces.c                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/08/10 12:49:25 by oel-ayad          #+#    #+#             */
/*   Updated: 2019/01/16 17:10:51 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

int		ft_is_separator(char c)
{
	if (c == ' ' || c == '\t' || c == '\n')
		return (1);
	return (0);
}

int		ft_cal_nb_word(char *str)
{
	int		i;
	int		nb_words;
	int		in_word;

	in_word = 0;
	i = 0;
	nb_words = 0;
	while (str[i])
	{
		if (ft_is_separator(str[i]) == 1)
			in_word = 0;
		else if (in_word == 0 && ft_is_separator(str[i]) == 0)
		{
			in_word = 1;
			nb_words++;
		}
		i++;
	}
	return (nb_words);
}

int		ft_calc_size_words(char *str, int i)
{
	int		size_words;

	size_words = 0;
	while (str[i++] && ft_is_separator(str[i]) == 0)
		size_words++;
	return (size_words + 1);
}

char	**ft_split_whitespaces(char *str)
{
	int			nb_words;
	int			k;
	int			i;
	int			j;
	char		**result;

	nb_words = 0;
	nb_words = ft_cal_nb_word(str);
	result = (char**)malloc(sizeof(char**) * (nb_words + 1));
	i = 0;
	k = 0;
	while (i < nb_words)
	{
		j = 0;
		while (ft_is_separator(str[k]) == 1)
			k++;
		result[i] = (char*)malloc(sizeof(char) *
				(ft_calc_size_words(str, k) + 1));
		while (ft_is_separator(str[k]) == 0 && str[k])
			result[i][j++] = str[k++];
		result[i][j] = '\0';
		i++;
	}
	result[i] = NULL;
	return (result);
}
