#include "ft_ssl.h"
#include "ft_encryption.h"


static int get_output_fd(struct s_command *command, int *fd)
{
	if (!(command->flags & FLAG_OUTPUTFILE))
	{
		*fd = STDOUT_FILENO;
		return FT_SSL_SUCCESS;
	}
	*fd = open(command->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (*fd < 0)
	{
		write_error3("Error opening file for writing", command->output_file, strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	return FT_SSL_SUCCESS;
}

static void output_base64_format(struct s_encryption *data, int fd)
{
	size_t written_bytes;

	for (written_bytes = 0; written_bytes + 64 < data->output_length; written_bytes += 64)
	{
		write(fd, data->result_buffer + written_bytes, 64);
		write(fd, &"\n", 1);
	}
	if (written_bytes < data->output_length)
	{
		write(fd, data->result_buffer + written_bytes, data->output_length - written_bytes);
		write(fd, &"\n", 1);
	}
}

int output_encryption_result(struct s_command *command, struct s_encryption *data)
{
	int fd;

	if (get_output_fd(command, &fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	if (!(command->flags & FLAG_DECODE) && command->flags & FLAG_BASE64_ENCRYPTION)
		output_base64_format(data, fd);
	else
		write(fd, data->result_buffer, data->output_length);
	if (fd != STDOUT_FILENO)
		close(fd);
	return FT_SSL_SUCCESS;
}

static void print_hex_dump(char *buffer, size_t length, int fd)
{
	char high;
	char low;
		
	for (size_t i = 0; i < length; i++) {
		high = "0123456789abcdef"[(buffer[i] >> 4) & 0x0F];
		low  = "0123456789abcdef"[buffer[i] & 0x0F];

		write(fd, &high, 1);
		write(fd, &low, 1);
	}
}

int print_debug_info(struct s_command *command, struct s_encryption *data)
{
	int fd;

	if (get_output_fd(command, &fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	ft_putstr_fd("KEY: ", fd);
	print_hex_dump(data->ksiv_buffer, data->key_length, fd);
	ft_putchar_fd('\n', fd);

	ft_putstr_fd("SALT: ", fd);
	print_hex_dump(data->ksiv_buffer + data->key_length, data->salt_length, fd);
	ft_putchar_fd('\n', fd);

	ft_putstr_fd("IV: ", fd);
	print_hex_dump(data->ksiv_buffer + data->key_length + data->salt_length, data->iv_length, fd);
	ft_putchar_fd('\n', fd);

	if (command->pass)
	{
		ft_putstr_fd("PASS: ", fd);
		ft_putstr_fd(command->pass, fd);
		ft_putchar_fd('\n', fd);
	}
	if (fd != STDOUT_FILENO)
		close (fd);
	return FT_SSL_SUCCESS;
}
