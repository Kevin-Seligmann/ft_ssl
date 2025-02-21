#include "ft_ssl.h"
#include "ft_encryption.h"

static void get_iv_from_bin_source(struct s_encryption *data, char *source, int input_length)
{
	char *vector_buffer;

	vector_buffer = data->ksiv_buffer + data->key_length + data->salt_length;
	memcpy(vector_buffer, source, input_length);
}

static void get_iv_from_source(struct s_encryption *data, char *source)
{
	size_t input_length;
	char *vector_buffer;

	vector_buffer = data->ksiv_buffer + data->key_length + data->salt_length;
	input_length = ft_strlen(source);
	copy_hexa((uint8_t *) vector_buffer, source, data->iv_length, input_length);
}

static int get_random_vector(struct s_encryption *data)
{
	char vector_buffer[DES_IV_LENGTH + 1];
	int fd;
	int read_bytes;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		write_error3("Error opening file", "/dev/urandom", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	read_bytes = read(fd, vector_buffer, DES_IV_LENGTH);
	if (read_bytes != DES_IV_LENGTH)
	{
		write_error2("Error reading from file", "/dev/urandom");
		return FT_SSL_FATAL_ERR;
	}
	get_iv_from_bin_source(data, vector_buffer, DES_IV_LENGTH);
	return FT_SSL_SUCCESS;
}

int get_initialization_vector(struct s_command *command, struct s_encryption *data)
{
	int ret;

	ret = FT_SSL_FATAL_ERR;
	if (command->flags & FLAG_VECTOR)
	{
		if (!is_hexa(command->vector, ft_strlen(command->vector)))
		{
			write_error("IV is not in hex. format");
			return FT_SSL_FATAL_ERR;
		}
		get_iv_from_source(data, command->vector);
		return FT_SSL_SUCCESS;
	}
	else
		ret = get_random_vector(data);
	if (ret == FT_SSL_FATAL_ERR)
		free(data->ksiv_buffer);
	return ret;
}
