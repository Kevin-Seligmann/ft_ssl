/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: kseligma <kseligma@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/12 19:22:34 by kseligma          #+#    #+#             */
/*   Updated: 2024/01/13 21:33:46 by kseligma         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

char	*ft_strjoin(char const *s1, char const *s2)
{
	char	*str;
	size_t	len1;
	size_t	len2;
	size_t	ind;

	if (s1 == 0 || s2 == 0)
		return (0);
	len1 = ft_strlen(s1);
	len2 = ft_strlen(s2);
	str = (char *) malloc(len1 + len2 + 1);
	if (str == 0)
		return (0);
	ind = 0;
	while (ind < len1)
	{
		str[ind] = s1[ind];
		ind ++;
	}
	while (ind < len1 + len2)
	{
		str[ind] = s2[ind - len1];
		ind ++;
	}
	str[ind] = 0;
	return (str);
}
