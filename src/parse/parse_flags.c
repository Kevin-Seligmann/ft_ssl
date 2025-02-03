#include "ft_ssl.h"
#include "ft_parse.h"
#include "ft_encryption.h"
#include "ft_hash.h"
#include "ft_encoding.h"

// Flag char, flag value, compatible commands, action.
//  struct s_flag_option {
// 	char *opt;
// 	int flag;
// 	int compatible_commands;
//	int needs_argument
//  int (*get_argument)();
// 	char *description;
// };

static struct s_flag_option hash_options[] = 
{
	{'p', HASH_FLAG_APPEND, COMM_TYPE_HASH, 0, 0, "Echoes STDIN to STDOUT and append the checksum to STDOUT"},
	{'q', HASH_FLAG_QUIET, COMM_TYPE_HASH, 0, 0, "Quiet mode"},
	{'r', HASH_FLAG_REVERSE, COMM_TYPE_HASH, 0, 0, "Reverse the format of the output"},
	{'s', HASH_FLAG_STRING_INPUT, COMM_TYPE_HASH, 1, get_s_opt_argument, "Hashes the next string"},
	{0, 0, 0, 0, NULL, NULL},
};

static struct s_flag_option encoding_options[] = 
{
	{'i', FLAG_INPUTFILE, COMM_TYPE_ENCODING, 1, get_input_file_argument, "Input file"},
	{'o', FLAG_OUTPUTFILE, COMM_TYPE_ENCODING, 1, get_output_file_argument, "Output file"},
	{'e', FLAG_ENCODE, COMM_TYPE_ENCODING, 0, 0, "Encode mode (Default)"},
	{'d', FLAG_DECODE, COMM_TYPE_ENCODING, 0, 0, "Decode mode"},
	{0, 0, 0, 0, NULL, NULL},
};

static struct s_flag_option crypt_options[] = 
{
	{'i', FLAG_INPUTFILE, COMM_TYPE_ENCRYPT, 1, get_input_file_argument, "Input file"},
	{'o', FLAG_OUTPUTFILE, COMM_TYPE_ENCRYPT, 1, get_output_file_argument, "Output file"},
	{'e', FLAG_ENCODE, COMM_TYPE_ENCRYPT, 0, 0, "Encode mode (Default)"},
	{'d', FLAG_DECODE, COMM_TYPE_ENCRYPT, 0, 0, "Decode mode"},
	{'a', FLAG_BASE64_ENCRYPTION, COMM_TYPE_ENCRYPT, 0, 0, "Encode/doce in base64"},
	{'k', FLAG_FLAG_KEY, COMM_TYPE_ENCRYPT, 1, get_crypt_key_argument, "Next argument is key in hex"},
	{'p', FLAG_PASSWORD, COMM_TYPE_ENCRYPT, 1, get_crypt_pass_argument, "Next argument is password in ASCII"},
	{'s', FLAG_SALT, COMM_TYPE_ENCRYPT, 1, get_crypt_salt_argument, "Targument is salt in hex"},
	{'v', FLAG_VECTOR, COMM_TYPE_ENCRYPT, 1, get_crypt_vector_argument, "Next argument is initialization vector in hex"},
	{0, 0, 0, 0, NULL, NULL},
};

static int is_flag(char *s)
{
	return (s && s[0] == '-' && s[1]);
}

static struct s_flag_option* get_option(char opt, struct s_command *command, struct s_flag_option *options)
{
	for (int i = 0; options[i].opt != 0; i++)
	{
		if (options[i].opt == opt)
			return &(options[i]);
	}
	write_error_wchar("Unrecognized option", opt);
	return NULL;
}

static void get_options_data(struct s_command *command, struct s_flag_option **options)
{
	switch (command->meta_info.command_type)
	{
		case COMM_TYPE_HASH: *options = hash_options; break;
		case COMM_TYPE_ENCODING: *options = encoding_options; break ;
		case COMM_TYPE_ENCRYPT: *options = crypt_options; break ;
	}
}

int parse_flags(struct s_command *command, int *ind, char **argv)
{
	struct s_flag_option *options;
	struct s_flag_option *opt;

	get_options_data(command, &options);
	while (is_flag(argv[*ind]))
	{
		for (int str_ind = 1; argv[*ind][str_ind]; str_ind ++)
		{
			opt = get_option(argv[*ind][str_ind], command, options);
			if (opt == NULL)
				return FT_SSL_FATAL_ERR;
			command->flags |= opt->flag;
			if (opt->needs_argument)
			{
				if (command->meta_info.command_type & COMM_TYPE_HASH)
					return opt->get_argument(command, ind, argv, str_ind);
				if (opt->get_argument(command, ind, argv, str_ind) == FT_SSL_FATAL_ERR)
					return FT_SSL_FATAL_ERR;
				break ;
			}
		}
		(*ind) ++;
	}
	return FT_SSL_SUCCESS;
}
