#include "ft_ssl.h"
#include "ft_asym.h"

static int initialize_command(struct s_command *command, struct s_genrsa_command *genrsa)
{
	genrsa->fd_rand = open("/dev/urandom", O_RDONLY);
	if (genrsa->fd_rand < 0)
	{
		write_error2("Opening /dev/urandom", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	if (command->flags & FLAG_OUTPUTFILE)
	{
		genrsa->fd_out = open(command->output_file, O_WRONLY);
		if (genrsa->fd_out < 0)
		{
			write_error3("Opening file", command->output_file, strerror(errno));
			return FT_SSL_FATAL_ERR;
		}
	}
	else 
		genrsa->fd_out = STDOUT_FILENO;
	return FT_SSL_SUCCESS;
}

static int exit_command(struct s_genrsa_command *genrsa, int ret)
{
	if (genrsa->fd_out != STDOUT_FILENO)
		close(genrsa->fd_out);
	close(genrsa->fd_rand);
	return ret;
}

static int generate_rsa_pkey(struct s_private_key *pkey, int rand_fd)
{
	BIGNUM *prime1_minus_one;
	BIGNUM *prime2_minus_one;
	BIGNUM *gcd_res;
	BIGNUM *lambda;
	BN_CTX *ctx;
	
	
	// Init.
	pkey->version = 0;
	pkey->modulus = BN_new();
	pkey->public_exponent = BN_new();
	lambda = BN_new();
	gcd_res = BN_new();
	pkey->private_exponent = BN_new();
	pkey->exponent_1 = BN_new();
	pkey->exponent_2 = BN_new();
	ctx = BN_CTX_new();

	// Gen prime 1.
	if (gen_prime(&(pkey->prime_1), rand_fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	prime1_minus_one = BN_dup(pkey->prime_1);
	BN_sub_word(prime1_minus_one, 1);

	// Gen prime 2.
	if (gen_prime(&(pkey->prime_2), rand_fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	prime2_minus_one = BN_dup(pkey->prime_2);
	BN_sub_word(prime2_minus_one, 1);

	// Set modulus
	BN_mul(pkey->modulus, pkey->prime_1, pkey->prime_2, ctx);

	// Set public exponent
	BN_set_word(pkey->public_exponent, GENRSA_PUBLIC_EXPONENT);

	// Set private exponent
	BN_mul(lambda, prime1_minus_one, prime2_minus_one, ctx);
	BN_gcd(gcd_res, prime1_minus_one, prime2_minus_one, ctx);
	BN_div(lambda, NULL, lambda, gcd_res, ctx);
	BN_mod_inverse(pkey->private_exponent, pkey->public_exponent, lambda, ctx);

	// Set CRT exponents and coefficient
	BN_mod(pkey->exponent_1, pkey->private_exponent, prime1_minus_one, ctx);
	BN_mod(pkey->exponent_2, pkey->private_exponent, prime2_minus_one, ctx);
	BN_mod_inverse(pkey->coefficient, pkey->prime_2, pkey->prime_1, ctx);

	return FT_SSL_SUCCESS;
}

int genrsa_command(struct s_command *command, int ind, char **argv)
{
	struct s_genrsa_command genrsa;

	if (initialize_command(command, &genrsa) == FT_SSL_FATAL_ERR)
		return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	if (generate_rsa_pkey(&genrsa.pkey, genrsa.fd_rand) == FT_SSL_FATAL_ERR)
		return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	// if (output_private_key(&genrsa) == FT_SSL_FATAL_ERR)
	// 	return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	return exit_command(&genrsa, FT_SSL_SUCCESS);
}
