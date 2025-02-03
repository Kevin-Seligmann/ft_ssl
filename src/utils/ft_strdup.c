/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: kseligma <kseligma@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/12 18:57:27 by kseligma          #+#    #+#             */
/*   Updated: 2024/01/13 20:13:05 by kseligma         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

char	*ft_strdup(const char *s1)
{
	size_t	len;
	size_t	ind;
	char	*cpy;
	char	*ptr;

	ptr = (char *) s1;
	len = ft_strlen(ptr);
	cpy = (char *) malloc(len + 1);
	if (cpy == 0)
		return (0);
	ind = 0;
	while (ind < len)
	{
		cpy[ind] = ptr[ind];
		ind ++;
	}
	cpy[ind] = 0;
	return (cpy);
}
