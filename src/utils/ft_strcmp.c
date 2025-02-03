#include "ft_ssl.h"

int	ft_strcmp(const char *s1, const char *s2)
{
	size_t	ind;

	ind = 0;
	while (*s1 && *s2)
	{
		if (s1[ind] == 0 || s2[ind] == 0 || s1[ind] != s2[ind])
			return ((unsigned char) s1[ind] - (unsigned char) s2[ind]);
		ind ++;
	}
	return (0);
}
