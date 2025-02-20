#ifndef FT_SSL_H

# define FT_SSL_H

# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <stdlib.h>
# include <fcntl.h>
# include <errno.h>
# include <stdint.h>

# define PROGRAM_NAME "FT_SSL"

// Types of command
# define COMM_TYPE_HASH 0x01
# define COMM_TYPE_ENCODING 0x02
# define COMM_TYPE_ENCRYPT 0x04
# define COMM_TYPE_GENRSA 0x08
# define COMM_TYPE_RSA 0x10
# define COMM_TYPE_RSAUTL 0x20
# define COMM_TYPE_GENDSA 0x40
# define COMM_TYPE_BREAKIT 0x80
# define COMM_TYPE_EXTRACTKEY 0x100

// Shared flags
# define FLAG_INPUTFILE 0x01
# define FLAG_OUTPUTFILE 0x02
# define FLAG_ENCODE 0x04
# define FLAG_DECODE 0x08
# define FLAG_FLAG_KEY 0x10
# define FLAG_PUBIN 0x20
# define FLAG_PASSOUT 0x40

// Encryption command flags.
# define FLAG_BASE64_ENCRYPTION 0x20
# define FLAG_PASSWORD 0x40
# define FLAG_SALT 0x80 
# define FLAG_VECTOR 0x100

// Hash command flags
# define HASH_FLAG_APPEND 0x01
# define HASH_FLAG_QUIET 0x02
# define HASH_FLAG_REVERSE 0x04
# define HASH_FLAG_STRING_INPUT 0x08
# define HASH_FLAG_FILE_INPUT 0x10
# define HASH_FLAG_STDIN_INPUT 0x20

// rsa flags
# define FLAG_INFORM 0x80
# define FLAG_OUTFORM 0x100
# define FLAG_PASSIN 0x200
# define FLAG_DES 0x400
# define FLAG_TEXT 0x800
# define FLAG_NOOUT 0x1000
# define FLAG_MODULUS 0x2000
# define FLAG_CHECK 0x4000
# define FLAG_POBOUT 0x8000
# define FLAG_TRADITIONAL 0x10000

// rsautl flags
# define FLAG_HEXDUMP 0x1

// gendsa flags
# define FLAG_GENDES 0x1

// Breakit/extractkey flags
# define FLAG_KEYSIZE 0x1
# define FLAG_ALGO 0x2
# define FLAG_PLAINTEXT 0x4

// Errors
# define FT_SSL_SUCCESS 0
# define FT_SSL_FATAL_ERR 1
# define FT_SSL_TRIVIAL_ERR 2

struct s_command;

struct s_command_info {
	char *command_name;
	int command_type;
	int (*command_function)(struct s_command *, int, char **);
	int algorithm;
	int (*algorithm_function)(void *);
};

struct s_command {
	struct s_command_info meta_info;
	union u_command_data *command;
	char *sopt_string;
	char *input_file;
	char *output_file;
	char *vector;
	char *salt;
	char *key;
	char *pass;
	int flags;
};

int parse(struct s_command *command, int *ind, char **argv);

// Error (No variadics or printfs allowed)
void write_error(char *err);
void write_error2(char *err, char *err2);
void write_error3(char *err, char *err2, char *err3);

// Utils
size_t	ft_strlen(const char *str);
void	ft_putstr_fd(char *s, int fd);
int		ft_strcmp(const char *s1, const char *s2);
int		ft_toupper(int c);
void 	ft_str_toupper(char *str);
void	ft_putchar_fd(char c, int fd);
void 	write_error_wchar(char *err, char c);
char 	*ft_strdup(const char *s1);
char 	*ft_read_file(int fd);
char 	*ft_read_bin(int fd, size_t *count);
char	*ft_strjoin(char const *s1, char const *s2);
void	*ft_memset(void *b, int c, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t n);
char	*ft_strchr(const char *s, int c);

#endif
