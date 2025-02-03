#include "ft_ssl.h"
#include "ft_encoding.h"

static int get_fd(struct s_command *command, struct s_encoding *data, int mode)
{
	int fd;

	if ((!(command->flags & FLAG_INPUTFILE) || !ft_strcmp(command->input_file, "-")) && mode == FLAG_INPUTFILE)
		return STDIN_FILENO;
	else if ((!(command->flags & FLAG_OUTPUTFILE) || !ft_strcmp(command->output_file, "-")) && mode == FLAG_OUTPUTFILE)
		return STDOUT_FILENO;
	else if (mode == FLAG_INPUTFILE)
		fd = open(command->input_file, O_RDONLY);	
	else if (mode == FLAG_OUTPUTFILE)
		fd = open(command->output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1 && mode == FLAG_INPUTFILE)
		write_error3("Error openning file", strerror(errno), command->input_file);
	if (fd == -1 && mode == FLAG_OUTPUTFILE)
		write_error3("Error openning file", strerror(errno), command->input_file);
	return fd;
}

static int get_input(struct s_command *command, struct s_encoding *data)
{
	int fd;

	data->output = NULL;
	data->input = NULL;
	fd = get_fd(command, data, FLAG_INPUTFILE);
	if (fd == -1)
		return FT_SSL_FATAL_ERR;
	data->input = ft_read_bin(fd, &(data->input_size));
	if (fd != STDIN_FILENO)
		close (fd);
	if (!data->input)
		return FT_SSL_FATAL_ERR;
	return FT_SSL_SUCCESS;
}

static int output_result(struct s_command *command, struct s_encoding *data, char *result)
{
	size_t printed_bytes;
	int fd;

	fd = get_fd(command, data, FLAG_OUTPUTFILE);
	if (fd == -1)
		return FT_SSL_FATAL_ERR;
	if (command->flags & FLAG_DECODE)
	{
		write (fd, result, data->output_size);
		return FT_SSL_SUCCESS;
	}
	for (printed_bytes = 0; printed_bytes < data->output_size; printed_bytes += 64)
	{
		if (data->output_size > 64 + printed_bytes)
			write (fd, result + printed_bytes, 64);
		else
			write (fd, result + printed_bytes, data->output_size - printed_bytes);
		ft_putchar_fd('\n', fd);
	}
	return FT_SSL_SUCCESS;
}

int encoding_command(struct s_command *command, int ind, char **argv)
{
	struct s_encoding data;
	int ret;
	
	data.flags = command->flags;
	if (command->flags & FLAG_ENCODE && command->flags & FLAG_DECODE)
	{
		write_error2(command->meta_info.command_name, "Incompatible encode and decode flags.");
		return FT_SSL_FATAL_ERR;
	}
	if (argv[ind])
	{
		write_error2(command->meta_info.command_name, "Invalid argument syntax.");
		return FT_SSL_FATAL_ERR;
	}
	if (get_input(command, &data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	ret = command->meta_info.algorithm_function(&data);
	if (ret == FT_SSL_SUCCESS)
		ret = output_result(command, &data, data.output);
	free(data.output);
	free(data.input);
	return ret;

}
