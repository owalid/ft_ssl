/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oel-ayad <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/11/09 13:26:17 by oel-ayad          #+#    #+#             */
/*   Updated: 2018/11/15 20:48:49 by oel-ayad         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int			nb_word(const char *str, char c)
{
	int		i;
	int		nb_words;
	int		in_word;

	i = 0;
	nb_words = 0;
	in_word = 0;
	while (str[i])
	{
		if (str[i] == c)
			in_word = 0;
		else if (in_word == 0 && str[i] != c)
		{
			in_word = 1;
			nb_words++;
		}
		i++;
	}
	return (nb_words);
}

static int			word(const char *str, int i, char c)
{
	int		size_words;

	size_words = 0;
	while (str[i++] && str[i] != c)
		size_words++;
	return (size_words);
}

char				**ft_strsplit(char const *s, char c)
{
	int			k;
	int			i;
	int			j;
	char		**r;

	if (!s || !c)
		return (NULL);
	if (!(r = (char**)malloc(sizeof(char*) * nb_word(s, c) + 1)))
		return (NULL);
	i = 0;
	k = 0;
	while (i < nb_word(s, c))
	{
		j = 0;
		while (s[k] == c)
			k++;
		if (!(r[i] = ft_strnew(sizeof(char) * word(s, k, c))))
			return (NULL);
		while (s[k] != c && s[k])
			r[i][j++] = s[k++];
		r[i++][j] = '\0';
	}
	r[i] = NULL;
	return (r);
}
