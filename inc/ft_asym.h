#ifndef ASYM_H
# define ASYM_H

// X.690

# include <openssl/bn.h>

# define KEY_BIT_SIZE 1024
# define GENRSA_PRIMALITY_ACCURACY 0.99999999999
# define GENRSA_PUBLIC_EXPONENT 65537
# define IS_EVEN(x) ((x & 0x1) == 0)


# define ENCODE_RSA_PRIV_KEY 1

struct s_private_key {
	int version;
	BIGNUM *modulus;
	BIGNUM *public_exponent;
	BIGNUM *private_exponent;
	BIGNUM *prime_1;
	BIGNUM *prime_2;
	BIGNUM *exponent_1;
	BIGNUM *exponent_2;
	BIGNUM *coefficient;
};

struct s_genrsa_command {
	struct s_private_key pkey;
	int fd_rand;
	int fd_out;
};

int rsautl_command(struct s_command *command, int ind, char **argv);
int rsa_command(struct s_command *command, int ind, char **argv);
int genrsa_command(struct s_command *command, int ind, char **argv);
int gendsa_command(struct s_command *command, int ind, char **argv);
int breakit_command(struct s_command *command, int ind, char **argv);
int extractkey_command(struct s_command *command, int ind, char **argv);

int gen_prime(BIGNUM **prime, int rand_fd);
int output_private_key(struct s_genrsa_command *genrsa);

#endif
	
	

