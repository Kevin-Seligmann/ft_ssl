#ifndef ASYM_H
# define ASYM_H

# define GENRSA_PRIMALITY_ACCURACY 0.99999999999
# define GENRSA_PUBLIC_EXPONENT 65537
# define IS_EVEN(x) ((x & 0x1) == 0)

int rsautl_command(struct s_command *command, int ind, char **argv);
int rsa_command(struct s_command *command, int ind, char **argv);
int genrsa_command(struct s_command *command, int ind, char **argv);
int gendsa_command(struct s_command *command, int ind, char **argv);
int breakit_command(struct s_command *command, int ind, char **argv);
int extractkey_command(struct s_command *command, int ind, char **argv);

int gen_prime_32b(uint32_t *prime, int rand_fd);

#endif
	
	

