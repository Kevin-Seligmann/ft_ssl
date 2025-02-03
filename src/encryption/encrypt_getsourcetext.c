#include "ft_ssl.h"
#include "ft_encryption.h"

static int pad_cfb(struct s_encryption *data)
{
	char *buffer;
	size_t pad_bytes;

	pad_bytes = (CIPHER_BLOCK_SIZE - data->input_length % CIPHER_BLOCK_SIZE) % CIPHER_BLOCK_SIZE;
	buffer = malloc(data->input_length + pad_bytes);
	if (buffer == 0)
	{
		write_error2("Memory error", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	ft_memcpy(buffer, data->source_buffer, data->input_length);
	ft_memset(buffer + data->input_length, 0, pad_bytes);
	free(data->source_buffer);
	data->source_buffer = buffer;
	return FT_SSL_SUCCESS;
}

static int pad_standard(struct s_encryption *data)
{
	char *buffer;
	size_t pad_bytes;

	pad_bytes = CIPHER_BLOCK_SIZE - data->input_length % CIPHER_BLOCK_SIZE;
	buffer = malloc(data->input_length + pad_bytes);
	if (buffer == 0)
	{
		write_error2("Memory error", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	ft_memcpy(buffer, data->source_buffer, data->input_length);
	ft_memset(buffer + data->input_length, pad_bytes, pad_bytes);
	free(data->source_buffer);
	data->source_buffer = buffer;
	data->input_length += pad_bytes;
	return FT_SSL_SUCCESS;
}

static int pad_buffer(struct s_encryption *data)
{
	if (data->cipher_mode == CFB_MODE || data->cipher_mode == OFB_MODE)
		return pad_cfb(data);
	else
		return pad_standard(data);
}

	// supposed_pad_bytes = data->source_buffer[data->input_length - 1];
	// if (supposed_pad_bytes > CIPHER_BLOCK_SIZE)
	// {
	// 	write_error("Invalid decoding input");
	// 	return FT_SSL_FATAL_ERR;
	// }
	// for (uint8_t found_pad_bytes = 0; found_pad_bytes < supposed_pad_bytes; found_pad_bytes ++)
	// {
	// 	if((uint8_t) data->source_buffer[data->input_length - 1 - found_pad_bytes] != supposed_pad_bytes)
	// 	{
	// 		write_error("Invalid decoding input");
	// 		return FT_SSL_FATAL_ERR;
	// 	}
	// }
	// data->input_length -= supposed_pad_bytes;

static int get_text_from_fd(int fd, struct s_encryption *data)
{
	data->source_buffer = ft_read_bin(fd, &(data->input_length));
	if (data->source_buffer == NULL)
		return FT_SSL_FATAL_ERR;
	if (data->flags & FLAG_DECODE && (data->cipher_mode == CFB_MODE || data->cipher_mode == OFB_MODE))
		return pad_cfb(data);
	else if (data->flags & FLAG_DECODE)
		return FT_SSL_SUCCESS;
	else
		return pad_buffer(data);
	return FT_SSL_SUCCESS;
}

int get_text_to_transform(struct s_command *command, struct s_encryption *data)
{
	int fd;
	int ret;

	if (!(command->flags & FLAG_INPUTFILE))
		return get_text_from_fd(STDIN_FILENO, data);
	fd = open(command->input_file, O_RDONLY);
	if (fd == -1)
	{
		write_error3("Error opening file", command->input_file, strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	ret = get_text_from_fd(fd, data);
	close(fd);
	return ret;
}	
