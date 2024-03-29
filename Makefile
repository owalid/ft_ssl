NAME	= ft_ssl

SRC		= main.c \
			md5.c sha224.c sha256.c sha384.c sha512.c \
			digest_process.c cipher_process.c \
			base64.c des_ecb.c des_cbc.c des_ofb.c des_cfb.c des_ctr.c \
			utils.c cipher_utils.c \
			pbkdf.c

OBJ		= $(addprefix $(OBJDIR),$(SRC:.c=.o))

CC		= gcc -g
CFLAGS	= -Wall -Wextra -Werror


FT		= ./libft/
FT_LIB	= $(addprefix $(FT),libft.a)
FT_INC	= -I ./libft
FT_LNK	= -L ./libft -l ft

SRCDIR	= ./src/
INCDIR	= ./includes/
OBJDIR	= ./obj/

all: $(NAME)

$(OBJDIR)%.o:$(SRCDIR)%.c $(INCDIR) Makefile
	mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(FT_INC) -o $@ -c $< -I $(INCDIR)

$(NAME): $(OBJ) 
	make -C $(FT) 
	$(CC) $(OBJ) $(FT_LNK) -lm -o $(NAME)

clean:
	rm -rf $(OBJDIR)
	make -C $(FT) clean

fclean: clean
	rm -rf $(NAME)
	make -C $(FT) fclean

re: fclean all

.PHONY: all obj fclean clean re
