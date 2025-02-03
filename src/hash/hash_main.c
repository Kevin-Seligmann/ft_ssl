#include "ft_ssl.h"
#include "ft_hash.h"

static void free_digest(struct hash_alg_data *data)
{
	if (data->digest != data->h)
		free(data->h);
	free(data->digest);
}

static void parse_input_sources(struct s_command *command, int ind, char **argv)
{
	if (argv[ind])
		command->flags |= HASH_FLAG_FILE_INPUT;
	if (!(command->flags & HASH_FLAG_STRING_INPUT) && !(command->flags & HASH_FLAG_FILE_INPUT))
		command->flags |= HASH_FLAG_STDIN_INPUT;
	if (command->flags & HASH_FLAG_APPEND)
		command->flags |= HASH_FLAG_STDIN_INPUT;
}

static int hash_string(struct s_command *command, uint8_t *str)
{
	struct hash_alg_data data;

	data.msg = str;
	command->meta_info.algorithm_function(&data);
	print_command_result(command, data.digest,(char *) str, HASH_PRINT_TYPE_STRING);
	free_digest(&data);
	return FT_SSL_SUCCESS;
}

static int hash_stdin(struct s_command *command)
{
	struct hash_alg_data data;
	int ret;

	data.msg = (uint8_t *) ft_read_file(STDIN_FILENO);
	if (!data.msg)
		return FT_SSL_FATAL_ERR;
	ret = command->meta_info.algorithm_function(&data);
	if (ret == FT_SSL_SUCCESS)
		print_command_result(command, data.digest, (char *) data.msg, HASH_PRINT_TYPE_STDIN);
	free(data.msg);
	free_digest(&data);
	return ret;
}

static int read_file(char **destination, char *file)
{
	int fd;

	fd = open(file, O_RDONLY);	
	if (fd == -1)
	{
		write_error3("Error opening file", strerror(errno), file);
		return FT_SSL_TRIVIAL_ERR; // Want to keep going anyways
	}
	*destination = ft_read_file(fd);
	close (fd);
	if (!*destination)
		return FT_SSL_FATAL_ERR;
	return FT_SSL_SUCCESS;
}

static int hash_file(struct s_command *command, char *file)
{
	struct hash_alg_data data;
	int ret;
	int fd;

	if (!ft_strcmp(file, "-"))
		return hash_stdin(command);
	ret = read_file((char **) &data.msg, file);
	if (ret == FT_SSL_TRIVIAL_ERR)
		return FT_SSL_SUCCESS;
	else if (ret == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	ret = command->meta_info.algorithm_function(&data);
	if (ret == FT_SSL_SUCCESS)
		print_command_result(command, data.msg, file, HASH_PRINT_TYPE_FILE);
	free(data.msg);
	free_digest(&data);
	return ret;
}

// Sugestion. Refactorize hashing so it can process in chunks. Being able to manage big files.
int hash_command(struct s_command *command, int ind, char **argv)
{
	int ret;

	ret = FT_SSL_SUCCESS;
	parse_input_sources(command, ind, argv);
	if (command->flags & HASH_FLAG_STDIN_INPUT)
		ret = hash_stdin(command);
	if (command->flags & HASH_FLAG_STRING_INPUT && ret == FT_SSL_SUCCESS)
		ret = hash_string(command, (uint8_t *) command->sopt_string);
	while (argv[ind] && ret == FT_SSL_SUCCESS)
		ret = hash_file(command, argv[ind++]);
	return ret;
}
