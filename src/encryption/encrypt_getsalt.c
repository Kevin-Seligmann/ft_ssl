#include "ft_ssl.h"
#include "ft_encryption.h"

static void get_salt_from_source(struct s_encryption *data, char *source)
{
	size_t input_length;
	char *salt_buffer;

	salt_buffer = data->ksiv_buffer + data->key_length;
	input_length = ft_strlen(source);
	copy_hexa((uint8_t *) salt_buffer, source, data->salt_length, input_length);
}

static int get_random_salt(struct s_encryption *data)
{
	char salt_buffer[DES_SALT_LENGTH + 1];
	int fd;
	int read_bytes;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
	{
		write_error3("Error opening file", "/dev/urandom", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	read_bytes = read(fd, salt_buffer, DES_SALT_LENGTH);
	if (read_bytes != DES_SALT_LENGTH)
	{
		write_error2("Error reading from file", "/dev/urandom");
		return FT_SSL_FATAL_ERR;
	}
	salt_buffer[DES_SALT_LENGTH] = 0;
	ft_memcpy(data->ksiv_buffer + data->key_length, read_bytes, DES_SALT_LENGTH);
	return FT_SSL_SUCCESS;
}
 
int get_salt(struct s_command *command, struct s_encryption *data)
{
	if (command->flags & FLAG_SALT)
		get_salt_from_source(data, command->salt);
	else
		return get_random_salt(data);
	return FT_SSL_SUCCESS;
}
