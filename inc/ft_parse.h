#ifndef FT_PARSE_H
# define FT_PARSE_H

struct s_flag_option {
	char *opt;
	int flag;
	int compatible_commands;
	int needs_argument;
	int (*get_argument)(struct s_command *, int *, char **);
	char *description;
};

int parse_flags(struct s_command *command, int *ind, char **argv);
int get_s_opt_argument(struct s_command *command, int *ind, char **argv);
int get_input_file_argument(struct s_command *command, int *ind, char **argv);
int get_output_file_argument(struct s_command *command, int *ind, char **argv);
int get_crypt_key_argument(struct s_command *command, int *ind, char **argv);
int get_crypt_pass_argument(struct s_command *command, int *ind, char **argv);
int get_crypt_vector_argument(struct s_command *command, int *ind, char **argv);
int get_crypt_salt_argument(struct s_command *command, int *ind, char **argv);

#endif
