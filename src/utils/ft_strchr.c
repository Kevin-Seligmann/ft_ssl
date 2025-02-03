/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: kseligma <kseligma@student.42barcel>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/01/11 19:23:59 by kseligma          #+#    #+#             */
/*   Updated: 2024/01/13 18:49:08 by kseligma         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

char	*ft_strchr(const char *s, int c)
{
	char	l;
	char	*ptr;

	ptr = (char *) s;
	l = (char) c;
	while (*ptr != l && *ptr != 0)
		ptr ++;
	if (*ptr == l)
		return (ptr);
	return (0);
}
