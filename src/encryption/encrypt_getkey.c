#include "ft_ssl.h"
#include "ft_encryption.h"
#include "ft_hash.h"

static void copy_key_from_source(struct s_encryption *data, char *source)
{
	size_t input_length;

	input_length = ft_strlen(source);
	copy_hexa((uint8_t *) data->ksiv_buffer, source, data->key_length, input_length);
}

static int get_key_from_md5(char *dest, size_t keylen, char *msg)
{
	struct hash_alg_data data;
	size_t copied_bytes;
	size_t digest_size;

	data.msg = (uint8_t *) msg;
	copied_bytes = 0;
	while (copied_bytes < keylen)
	{
		if (hash_md5((void *) &data) == FT_SSL_FATAL_ERR)
			return FT_SSL_FATAL_ERR;
		digest_size = (data.hash_values_bit_size * data.hash_values_qty) / 8;
		if (digest_size + copied_bytes <= keylen)
			ft_memcpy((uint8_t *) (dest + copied_bytes), data.digest, digest_size);
		else
			ft_memcpy((uint8_t *) (dest + copied_bytes), data.digest, keylen - copied_bytes);
		copied_bytes += digest_size;
		free(data.digest);
	}
	return FT_SSL_SUCCESS;
}

static int get_key_from_pbkfd1(struct s_encryption *data, char *password)
{
	char *message;
	size_t pass_length;
	size_t total_length;
	int ret;

	pass_length = ft_strlen(password);
	total_length = pass_length + data->salt_length;
	message = malloc(total_length + 1);
	if (message == NULL)
	{
		write_error2("Memory error", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	ft_memcpy(message, password, pass_length);
	ft_memcpy(message + pass_length, data->ksiv_buffer + data->key_length, data->salt_length);
	message[total_length] = 0;
	ret = get_key_from_md5(data->ksiv_buffer, data->key_length, message);
	free(message);
	return ret;
}

static int get_key_from_input_password(struct s_command *command, struct s_encryption *data)
{
	return get_key_from_pbkfd1(data, command->pass);
}

static int get_key_from_stdin_password(struct s_encryption *data)
{
	char *password;

	password = getpass("Enter encryption password: ");
	if (password == NULL)
	{
		write_error2("Error retrieving password", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	return get_key_from_pbkfd1(data, password);
}

int	get_keys(struct s_command *command, struct s_encryption *data)
{
	if (command->flags & FLAG_FLAG_KEY)
	{
		if (!is_hexa(command->key, ft_strlen(command->key)))
		{
			write_error("Key is not in hex. format");
			return FT_SSL_FATAL_ERR;
		}
		copy_key_from_source(data, command->key);
	}
	else if (command->flags & FLAG_PASSWORD)
		return get_key_from_input_password(command, data);
	else
		return get_key_from_stdin_password(data);
	return FT_SSL_SUCCESS;
}
