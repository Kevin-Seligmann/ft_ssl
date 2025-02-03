#include "ft_ssl.h"
#include "ft_parse.h"

static char *get_str_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	if (argv[*ind][str_ind + 1])
	{
		argument = &(argv[*ind][str_ind + 1]);
		return argument;
	}
	if (!argv[(*ind) + 1])
	{
		write_error_wchar("Argument required for option", argv[*ind][str_ind]);
		return NULL;
	}
	argument = argv[(*ind) + 1];
	(*ind) += 1;
	return argument;
}

static int set_argument(char *argument, char **destination)
{
	if (argument == NULL)
		return (FT_SSL_FATAL_ERR);
	*destination = argument;
	return FT_SSL_SUCCESS;
}

int get_input_file_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->input_file);

}

int get_output_file_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->output_file);
}

int get_s_opt_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;
	int ret;

	argument = get_str_argument(command, ind, argv, str_ind);
	ret = set_argument(argument, &command->sopt_string);
	(*ind) += 1;
	return ret;
}

int get_crypt_key_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->key);
}

int get_crypt_pass_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->pass);
}

int get_crypt_vector_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->vector);
}

int get_crypt_salt_argument(struct s_command *command, int *ind, char **argv, int str_ind)
{
	char *argument;

	argument = get_str_argument(command, ind, argv, str_ind);
	return set_argument(argument, &command->salt);
}
