/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memset.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: kseligma <kseligma@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/09 18:04:54 by kseligma          #+#    #+#             */
/*   Updated: 2024/01/13 17:34:46 by kseligma         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

void	*ft_memset(void *b, int c, size_t len)
{
	unsigned char	byte;
	size_t			count;

	byte = (unsigned char) c;
	count = 0;
	while (count < len)
	{
		((char *) b)[count] = byte;
		count ++;
	}
	return (b);
}
