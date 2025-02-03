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

// Types of hash algorithm
# define HASH_ALG_MD5 0x01
# define HASH_ALG_SHA224 0x02
# define HASH_ALG_SHA256 0x04
# define HASH_ALG_SHA384 0x08
# define HASH_ALG_SHA512 0x10
# define HASH_ALG_SHA512_224 0x20
# define HASH_ALG_SHA512_256 0x40
# define HASH_ALG_WHIRLPOOL 0x80

// Types of encoding algorithms
# define ENC_ALG_BASE64 0x01
# define DEC_ALG_BASE64 0x02

// Types of simmetric crypt. algorithms
# define SIM_ENC_ALG_DES_ECB 0x1
# define SIM_ENC_ALG_DES_CBC 0x2
# define SIM_ENC_ALG_DES_PCBC 0x4
# define SIM_ENC_ALG_DES_CFB 0x8
# define SIM_ENC_ALG_DES_OFB 0x40
# define SIM_ENC_ALG_DES_CTR 0x80
# define SIM_ENC_ALG_DES_EDE_ECB 0x100
# define SIM_ENC_ALG_DES_EDE_CBC 0x200
# define SIM_ENC_ALG_DES_EDE_PCBC 0x400
# define SIM_ENC_ALG_DES_EDE_CFB 0x800
# define SIM_ENC_ALG_DES_EDE_OFB 0x4000
# define SIM_ENC_ALG_DES_EDE_CTR 0x8000
# define SIM_ENC_ALG_DES_EDE3_ECB 0x10000
# define SIM_ENC_ALG_DES_EDE3_CBC 0x20000
# define SIM_ENC_ALG_DES_EDE3_PCBC 0x40000
# define SIM_ENC_ALG_DES_EDE3_CFB 0x80000
# define SIM_ENC_ALG_DES_EDE3_OFB 0x400000
# define SIM_ENC_ALG_DES_EDE3_CTR 0x800000


// Hash command flags
# define HASH_FLAG_APPEND 0x01
# define HASH_FLAG_QUIET 0x02
# define HASH_FLAG_REVERSE 0x04
# define HASH_FLAG_STRING_INPUT 0x08
# define HASH_FLAG_FILE_INPUT 0x10
# define HASH_FLAG_STDIN_INPUT 0x20

// Encoding command flags
# define FLAG_INPUTFILE 0x01
# define FLAG_OUTPUTFILE 0x02
# define FLAG_ENCODE 0x04
# define FLAG_DECODE 0x08

// Encryption command flags.
# define FLAG_BASE64_ENCRYPTION 0x10
# define FLAG_FLAG_KEY 0x20
# define FLAG_PASSWORD 0x40
# define FLAG_SALT 0x80 
# define FLAG_VECTOR 0x100

// Printing function need this
# define HASH_PRINT_TYPE_STRING 0x01
# define HASH_PRINT_TYPE_STDIN 0x02
# define HASH_PRINT_TYPE_FILE 0x04
# define PRINT_PARENTHESIS 0x01
# define PRINT_QUOTES 0x02
# define PRINT_TRAILING_NL 0x04

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

struct s_flag_option {
	char opt;
	int flag;
	int compatible_commands;
	int needs_argument;
	int (*get_argument)(struct s_command *, int *, char **, int);
	char *description;
};

int parse(struct s_command *command, int *ind, char **argv);
int parse_flags(struct s_command *command, int *ind, char **argv);

// (No variadics or printfs allowed) (Could be a struct with many strings)
void write_error(char *err);
void write_error2(char *err, char *err2);
void write_error3(char *err, char *err2, char *err3);

// Libft utils
size_t ft_strlen(const char *str);
void	ft_putstr_fd(char *s, int fd);
int	ft_strcmp(const char *s1, const char *s2);
int	ft_toupper(int c);
void ft_str_toupper(char *str);
void	ft_putchar_fd(char c, int fd);
void write_error_wchar(char *err, char c);
char *ft_strdup(const char *s1);
char *ft_read_file(int fd);
char *ft_read_bin(int fd, size_t *count);
char	*ft_strjoin(char const *s1, char const *s2);
void	*ft_memset(void *b, int c, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t n);
char	*ft_strchr(const char *s, int c);

// Hashes functions
int hash_command(struct s_command *command, int ind, char **argv);
int hash_md5(void *data);
int hash_sha224(void *data);
int hash_sha256(void *data);
int hash_sha384(void *data);
int hash_sha512(void *data);
int hash_sha512_224(void *data);
int hash_sha512_256(void *data);
int hash_whirlpool(void *data);

// Encoding functions
int encoding_command(struct s_command *command, int ind, char **argv);
int encoding_base64(void *data);

// Encryption functions
int encryption_command(struct s_command *command, int ind, char **argv);
int des_ecb_command(void *data);
int des_cbc_command(void *data);
int des_pcbc_command(void *data);
int des_ofb_command(void *data);
int des_cfb_command(void *data);
int des_ctr_command(void *data);
int des_ede_ecb_command(void *data);
int des_ede_cbc_command(void *data);
int des_ede_pcbc_command(void *data);
int des_ede_cfb_command(void *data);
int des_ede_ofb_command(void *data);
int des_ede_ctr_command(void *data);
int des_ede3_ecb_command(void *data);
int des_ede3_cbc_command(void *data);
int des_ede3_pcbc_command(void *data);
int des_ede3_cfb_command(void *data);
int des_ede3_ofb_command(void *data);
int des_ede3_ctr_command(void *data);


#endif
