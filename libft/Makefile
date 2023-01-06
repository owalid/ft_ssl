# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/01/30 15:43:53 by oel-ayad          #+#    #+#              #
#    Updated: 2023/01/06 13:40:24 by oel-ayad         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

SRCS =	ft_memset.c \
		ft_bzero.c \
		ft_memset.c \
		ft_bzero.c \
		ft_memccpy.c \
		ft_memchr.c \
		ft_memcmp.c \
		ft_strlen.c \
		ft_strdup.c \
		ft_strcpy.c \
		ft_strncpy.c \
		ft_strcat.c \
		ft_strncat.c \
		ft_strlcat.c \
		ft_strchr.c \
		ft_strrchr.c \
		ft_strstr.c \
		ft_strnstr.c \
		ft_strcmp.c \
		ft_strncmp.c \
		ft_atoi.c \
		ft_isalpha.c \
		ft_isdigit.c \
		ft_isalnum.c \
		ft_isascii.c \
		ft_isprint.c \
		ft_toupper.c \
		ft_tolower.c \
		ft_memalloc.c \
		ft_memdel.c \
		ft_strnew.c \
		ft_strdel.c \
		ft_strclr.c \
		ft_striter.c \
		ft_striteri.c \
		ft_strmap.c \
		ft_strmapi.c \
		ft_strsub.c \
		ft_strjoin.c \
		ft_strtrim.c \
		ft_strsplit.c \
		ft_itoa.c \
		ft_putchar.c \
		ft_putstr.c \
		ft_putendl.c \
		ft_putnbr.c \
		ft_putchar_fd.c \
		ft_putstr_fd.c \
		ft_putendl_fd.c \
		ft_putnbr_fd.c \
		ft_strequ.c \
		ft_strnequ.c \
		ft_lstadd.c \
		ft_lstdel.c \
		ft_lstdelone.c \
		ft_lstiter.c \
		ft_lstmap.c \
		ft_lstnew.c \
		ft_memcpy.c \
		ft_memmove.c \
		ft_strcapitalize.c \
		ft_isxdigit.c \
		ft_isspace.c \
		ft_isupper.c \
		ft_isgraph.c \
		ft_isblank.c \
		ft_itoa_base.c \
		ft_utoa_base.c \
		ft_str_is_alpha.c \
		ft_str_is_lowercase.c \
		ft_str_is_numeric.c \
		ft_str_is_printable.c \
		ft_str_is_uppercase.c \
		ft_strcasecmp.c \
		ft_strlowcase.c \
		ft_strncasecmp.c \
		ft_strndup.c \
		ft_strupcase.c \
		ft_islower.c \
		ft_strncasecmp.c \
		ft_strlowcase.c \
		ft_strnlowcase.c \
		ft_strndup.c \
		ft_lst_pushback.c \
		ft_strrev.c \
		ft_sort_integer_table.c \
		ft_lstsize.c \
		ft_lstget_at.c \
		ft_lstfind.c \
		ft_swap.c \
		ft_del_tab.c \
		ft_split_whitespaces.c \
		ft_tab_len.c \
		ft_hextoi.c \

OBJ = $(SRCS:.c=.o)

FLAG = -Wall -Wextra -Werror

all: $(NAME)

$(NAME): $(OBJ)
	gcc $(FLAG) -c $(SRCS)
	ar rc $(NAME) $(OBJ)
	ranlib $(NAME)

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all obj fclean clean re
