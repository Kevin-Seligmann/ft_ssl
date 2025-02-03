#ifndef FT_PARSE_H
# define FT_PARSE_H

int get_s_opt_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_input_file_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_output_file_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_crypt_key_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_crypt_pass_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_crypt_vector_argument(struct s_command *command, int *ind, char **argv, int str_ind);
int get_crypt_salt_argument(struct s_command *command, int *ind, char **argv, int str_ind);

#endif
