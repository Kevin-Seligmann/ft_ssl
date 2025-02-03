/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: kseligma <kseligma@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/09 19:17:43 by kseligma          #+#    #+#             */
/*   Updated: 2024/01/17 18:18:43 by kseligma         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t	count;

	count = 0;
	if (!dst && !src && n > 0)
		return (0);
	while (count < n)
	{
		((char *) dst)[count] = ((char *) src)[count];
		count ++;
	}
	return (dst);
}
