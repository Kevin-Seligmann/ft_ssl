#include "ft_ssl.h"

#define ERR_SEPARATOR ": "

// Printf types not allowed.
void write_error(char *err)
{
	ft_putstr_fd(PROGRAM_NAME, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err, STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
}

void write_error2(char *err, char *err2)
{
	ft_putstr_fd(PROGRAM_NAME, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err2, STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
}

void write_error3(char *err, char *err2, char *err3)
{
	ft_putstr_fd(PROGRAM_NAME, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err2, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err3, STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
}


void write_error_wchar(char *err, char c)
{
	ft_putstr_fd(PROGRAM_NAME, STDERR_FILENO);
	ft_putstr_fd(ERR_SEPARATOR, STDERR_FILENO);
	ft_putstr_fd(err, STDERR_FILENO);
	ft_putstr_fd(" ('", STDERR_FILENO);
	ft_putchar_fd(c, STDERR_FILENO);
	ft_putstr_fd("')", STDERR_FILENO);
	ft_putstr_fd("\n", STDERR_FILENO);
}
