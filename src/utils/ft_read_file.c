# include "ft_ssl.h"

# define FT_BFSIZE 20000

static char *bindup(char *src, size_t size)
{
	char *dst;

	dst = malloc(size);
	if (!dst)
		return NULL;
	ft_memcpy(dst, src, size);
	return dst;
}

static char *binjoin(char *left, char *right, size_t l_size, size_t r_size)
{
	char *dst;

	dst = malloc(l_size + r_size);
	if (!dst)
		return NULL;
	ft_memcpy(dst, left, l_size);
	ft_memcpy(dst + l_size, right, r_size);
	return dst;
}

char *ft_read_bin(int fd, size_t *count)
{
	char buffer[FT_BFSIZE];
	char *result;
	char *aux;
	ssize_t bytes_read;

	result = NULL;
	bytes_read = -1;
	*count = 0;
	while (bytes_read != 0)
	{
		bytes_read = read(fd, buffer, FT_BFSIZE);
		if (bytes_read < 0)
		{
			write_error2("Error reading file", strerror(errno));
			free(result);
			return NULL;
		}
		if (result == NULL)
			result = bindup(buffer, bytes_read);
		else if (bytes_read > 0)
		{
			aux = binjoin(result, buffer, (*count), bytes_read);
			free(result);
			result = aux;
		}
		if (result == NULL)
		{
			write_error2("Memory error", strerror(errno));
			return NULL;
		}
		(*count) += bytes_read;
	}
	return result;
}

char *ft_read_file(int fd)
{
	char buffer[FT_BFSIZE + 1];
	char *result;
	char *aux;
	ssize_t bytes_read;

	result = NULL;
	bytes_read = -1;
	while (bytes_read != 0)
	{
		bytes_read = read(fd, buffer, FT_BFSIZE);
		if (bytes_read < 0)
		{
			write_error2("Error reading file", strerror(errno));
			free(result);
			return NULL;
		}
		buffer[bytes_read] = 0;
		if (result == NULL)
			result = ft_strdup(buffer);
		else if (bytes_read > 0)
		{
			aux = result;
			result = ft_strjoin(aux, buffer);
			free(aux);
		}
		if (result == NULL)
		{
			write_error2("Memory error", strerror(errno));
			return NULL;
		}
	}
	return result;
}
