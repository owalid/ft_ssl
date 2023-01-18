echo -n $1 | ./ft_ssl des-ecb -v 0123456789ABCDEF -k 0123456789ABCDEF | ./ft_ssl des-ecb -k 0123456789ABCDEF -v 0123456789ABCDEF -d && echo -n "\n\nstr size = " && echo -n $1 | wc -c


# echo -n $1 | ./ft_ssl des-ofb -v 0123456789ABCDEF -k 0123456789ABCDEF -a | ./ft_ssl des-ofb -k 0123456789ABCDEF -v 0123456789ABCDEF -a -d | wc -c && echo -n "\n\nstr size = " && echo -n $1 | wc -c