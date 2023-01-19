#include "libft.h"


size_t      ft_hextol(char *str)
{
	size_t		    result = 0;
    int             len_str = ft_strlen(str);

    for (int i = 0; i < len_str; i++)
    {
        if (str[i] >= '0' && str[i] <= '9')
            result = result * 16 + (str[i] - '0');
        else if (str[i] >= 'a' && str[i] <= 'f')
            result = result * 16 + (str[i] - 'a' + 10);
        else if (str[i] >= 'A' && str[i] <= 'F')
            result = result * 16 + (str[i] - 'A' + 10);
    }

	return result;
}
