# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: oel-ayad <oel-ayad@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/01/30 15:43:53 by oel-ayad          #+#    #+#              #
#    Updated: 2023/01/19 11:27:05 by oel-ayad         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

SRCS =	ft_memset.c \
		ft_bzero.c \
		ft_memcpy.c \
		ft_strlen.c \
		ft_strnew.c \
		ft_strcpy.c \
		ft_strncpy.c \
		ft_atoi.c \
		ft_putstr.c \
		ft_putstr_fd.c \
		ft_putchar.c \
		ft_putchar_fd.c \
		ft_strcmp.c \
		ft_strlowcase.c \
		ft_utoa_base.c \
		ft_itoa_base.c \
		ft_hextol.c \
		ft_memalloc.c \
		ft_strupcase.c \
		ft_isspace.c \
		ft_isupper.c \
		ft_toupper.c \
		ft_tolower.c \
		ft_islower.c	

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
