#include "ft_ssl.h"

int main (int argc, char **argv)
{
	static struct s_command command;
	int ret;
	int ind;

	if (parse(&command, &ind, argv) == FT_SSL_FATAL_ERR)
		return (EXIT_FAILURE);
	ret = command.meta_info.command_function(&command, ind, argv);
	if (ret == FT_SSL_FATAL_ERR)
		return (EXIT_FAILURE);
	return (EXIT_SUCCESS);
}
