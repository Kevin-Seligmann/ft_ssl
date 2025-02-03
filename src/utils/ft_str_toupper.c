#include "ft_ssl.h"

void ft_str_toupper(char *str)
{
	while (*str)
	{
		*str = ft_toupper(*str);
		str ++;
	}
}
