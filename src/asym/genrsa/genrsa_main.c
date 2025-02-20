#include "ft_ssl.h"
#include "ft_asym.h"

// Private key generation
static int exit_rsa_pkey_generation(int ret, BIGNUM *gcd_res, BIGNUM *lambda, BN_CTX *ctx)
{
	BN_free(gcd_res);
	BN_free(lambda);
	BN_CTX_free(ctx);
	return ret;
}

static int generate_rsa_pkey(struct s_private_key *pkey, int rand_fd)
{
	int ret;
	BIGNUM *gcd_res;
	BIGNUM *lambda;
	BN_CTX *ctx;
	
	// Init.
	lambda = BN_new();
	gcd_res = BN_new();
	ctx = BN_CTX_new();

	if (lambda == 0 || gcd_res == 0 || ctx == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Gen prime 1.
	if (gen_prime(&(pkey->prime_1), rand_fd) == FT_SSL_FATAL_ERR)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Gen prime 2.
	if (gen_prime(&(pkey->prime_2), rand_fd) == FT_SSL_FATAL_ERR)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Set modulus
	if (BN_mul(pkey->modulus, pkey->prime_1, pkey->prime_2, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Set public exponent
	if(BN_set_word(pkey->public_exponent, GENRSA_PUBLIC_EXPONENT) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	
	// Temporary subtract one for both primes for next operations
	if(BN_sub_word(pkey->prime_1, 1) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	if(BN_sub_word(pkey->prime_2, 1) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	
	// Set private exponent
	if(BN_mul(lambda, pkey->prime_1, pkey->prime_2, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	if(BN_gcd(gcd_res, pkey->prime_1, pkey->prime_2, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	if(BN_div(lambda, NULL, lambda, gcd_res, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	if(BN_mod_inverse(pkey->private_exponent, pkey->public_exponent, lambda, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);


	// Set CRT exponents
	if(BN_mod(pkey->exponent_1, pkey->private_exponent, pkey->prime_1, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);
	if(BN_mod(pkey->exponent_2, pkey->private_exponent, pkey->prime_2, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Re-add one to primes
	if(BN_add_word(pkey->prime_1, 1) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	if(BN_add_word(pkey->prime_2, 1) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	// Set coefficient
	if(BN_mod_inverse(pkey->coefficient, pkey->prime_2, pkey->prime_1, ctx) == 0)
		return exit_rsa_pkey_generation(FT_SSL_FATAL_ERR, gcd_res, lambda, ctx);

	return exit_rsa_pkey_generation(FT_SSL_SUCCESS, gcd_res, lambda, ctx);
}

// GENRSA Command
static int initialize_genrsa_command(struct s_command *command, struct s_genrsa_command *genrsa)
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
	genrsa->pkey.version = 0;
	genrsa->pkey.modulus = BN_new();
	genrsa->pkey.public_exponent = BN_new();
	genrsa->pkey.private_exponent = BN_new();
	genrsa->pkey.exponent_1 = BN_new();
	genrsa->pkey.exponent_2 = BN_new();
	genrsa->pkey.coefficient = BN_new();
	genrsa->pkey.prime_1 = BN_new();
	genrsa->pkey.prime_2 = BN_new();

	if (genrsa->pkey.modulus == 0 || \
		genrsa->pkey.public_exponent == 0 || \
		genrsa->pkey.private_exponent == 0 || \
		genrsa->pkey.exponent_1 == 0 || \
		genrsa->pkey.exponent_2 == 0 || \
		genrsa->pkey.coefficient == 0 || \
		genrsa->pkey.prime_1 == 0 || \
		genrsa->pkey.prime_2 == 0)
	{
		write_error("Memory error");
		return FT_SSL_FATAL_ERR;
	}
	return FT_SSL_SUCCESS;
}

static int exit_genrsa_command(struct s_genrsa_command *genrsa, int ret)
{
	if (genrsa->fd_out != STDOUT_FILENO)
		close(genrsa->fd_out);
	close(genrsa->fd_rand);
	BN_free(genrsa->pkey.modulus);
	BN_free(genrsa->pkey.private_exponent);
	BN_free(genrsa->pkey.public_exponent);
	BN_free(genrsa->pkey.prime_1);
	BN_free(genrsa->pkey.prime_2);
	BN_free(genrsa->pkey.exponent_1);
	BN_free(genrsa->pkey.exponent_2);
	BN_free(genrsa->pkey.coefficient);
	return ret;
}

int genrsa_command(struct s_command *command, int ind, char **argv)
{
	struct s_genrsa_command genrsa;

	if (argv[ind])
	{
		write_error2(command->meta_info.command_name, "Invalid argument syntax.");
		return FT_SSL_FATAL_ERR;
	}
	if (initialize_genrsa_command(command, &genrsa) == FT_SSL_FATAL_ERR)
		return exit_genrsa_command(&genrsa, FT_SSL_FATAL_ERR);
	if (generate_rsa_pkey(&genrsa.pkey, genrsa.fd_rand) == FT_SSL_FATAL_ERR)
	{
		write_error("Memory error generating private key");
		return exit_genrsa_command(&genrsa, FT_SSL_FATAL_ERR);
	}
	if (output_private_key(&genrsa) == FT_SSL_FATAL_ERR)
		return exit_genrsa_command(&genrsa, FT_SSL_FATAL_ERR);
	return exit_genrsa_command(&genrsa, FT_SSL_SUCCESS);
}
