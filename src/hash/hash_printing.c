#include "ft_ssl.h"
#include "ft_hash.h"

static void print_digest(uint8_t *digest, size_t bytes)
{
	for (size_t i = 0; i < bytes; i ++)
	{
		write(STDOUT_FILENO, "0123456789abcdef" + (((*(digest + i)) >> 4) & 0xF), 1);
		write(STDOUT_FILENO, "0123456789abcdef" + ((*(digest + i)) & 0xF), 1);
	}
}

static void print_digest_r(uint8_t *digest, size_t bytes, int wordsize)
{
	for (size_t i = 0; i < bytes; i += wordsize)
	{
		for (int j = wordsize - 1; j >= 0; j --)
		{
			write(STDOUT_FILENO, "0123456789abcdef" + (((*(digest + j + i)) >> 4) & 0xF), 1);
			write(STDOUT_FILENO, "0123456789abcdef" + ((*(digest + j + i)) & 0xF), 1);
			if (i + j == bytes)
				return ;
		}
	}
}

static void print_generic_digest(struct s_command *command, uint8_t *dig)
{
	switch (command->meta_info.algorithm)
	{
		case HASH_ALG_SHA224: print_digest_r(dig, 224 / 8, 4); break;
		case HASH_ALG_SHA256: print_digest_r(dig, 256 / 8, 4); break;
		case HASH_ALG_SHA384: print_digest_r(dig, 384 / 8, 8); break;
		case HASH_ALG_SHA512: print_digest_r(dig, 512 / 8, 8); break;
		case HASH_ALG_SHA512_224: print_digest_r(dig, 224 / 8, 8); break;
		case HASH_ALG_SHA512_256: print_digest_r(dig, 256 / 8, 8); break;
		case HASH_ALG_MD5: print_digest(dig, 16); break;
		case HASH_ALG_WHIRLPOOL: print_digest(dig, 64); break;
	}
}

void put_without_newline(char *msg)
{
	size_t len;
	
	len = ft_strlen(msg);
	if (msg[len - 1] == '\n')
		len --;
	write(STDOUT_FILENO, msg, len);
}

static void print_command_name(char *name)
{
	ft_putstr_fd(name, STDOUT_FILENO);
	ft_putchar_fd(' ', STDOUT_FILENO);
}

static void print_source(char *source, int print_flag)
{
	if (print_flag & PRINT_PARENTHESIS)
		ft_putchar_fd('(', STDOUT_FILENO);
	if (print_flag & PRINT_QUOTES)
		ft_putchar_fd('"', STDOUT_FILENO);
	if (print_flag & PRINT_TRAILING_NL)
		put_without_newline(source);
	else
		ft_putstr_fd(source, STDOUT_FILENO);
	if (print_flag & PRINT_QUOTES)
		ft_putchar_fd('"', STDOUT_FILENO);
	if (print_flag & PRINT_PARENTHESIS)
		ft_putchar_fd(')', STDOUT_FILENO);
}

static void print_command_info(struct s_command *command, char *source, int print_type)
{
	if (print_type == HASH_PRINT_TYPE_STDIN)
	{
		if (command->flags & HASH_FLAG_APPEND) 
			print_source(source, PRINT_QUOTES | PRINT_PARENTHESIS | PRINT_TRAILING_NL);
		else 
			print_source("stdin", PRINT_PARENTHESIS);
		ft_putstr_fd("=", STDOUT_FILENO);
	}
	else if (print_type == HASH_PRINT_TYPE_FILE)
	{
		if (command->flags & HASH_FLAG_REVERSE)
			print_source(source, 0);
		else
		{
			print_command_name(command->meta_info.command_name);
			print_source(source, PRINT_PARENTHESIS);
			ft_putstr_fd(" =", STDOUT_FILENO);
		}
	}
	else if (print_type == HASH_PRINT_TYPE_STRING)
	{
		if (command->flags & HASH_FLAG_REVERSE)
			print_source(source, PRINT_QUOTES);
		else
		{
			print_command_name(command->meta_info.command_name);
			print_source(source, PRINT_QUOTES | PRINT_PARENTHESIS);
			ft_putstr_fd(" =", STDOUT_FILENO);
		}
	}
}

void print_command_result(struct s_command *command, uint8_t *digest, char *source, int print_type)
{
	if ((command->flags & HASH_FLAG_QUIET))
	{
		if ((command->flags & HASH_FLAG_APPEND) && print_type == HASH_PRINT_TYPE_STDIN)
			print_source(source, 0);
		print_generic_digest(command, digest);
	}
	else if ((command->flags & HASH_FLAG_REVERSE) && !(print_type == HASH_PRINT_TYPE_STDIN))
	{
		print_generic_digest(command, digest);
		ft_putchar_fd(' ', STDOUT_FILENO);
		print_command_info(command, source, print_type);
	}
	else 
	{
		print_command_info(command, source, print_type);
		ft_putchar_fd(' ', STDOUT_FILENO);
		print_generic_digest(command, digest);
	}
	ft_putchar_fd('\n', STDOUT_FILENO);
}
