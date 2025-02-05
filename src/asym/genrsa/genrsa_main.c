#include "ft_ssl.h"
#include "ft_asym.h"

struct s_private_key {
	uint64_t version;
	uint64_t modulus;
	uint64_t public_exponent;
	uint64_t private_exponent;
	uint32_t prime_1;
	uint32_t prime_2;
	uint64_t exponent_1;
	uint64_t exponent_2;
	uint64_t coefficient;
};

struct s_genrsa_command {
	struct s_private_key pkey;
	int fd_rand;
	int fd_out;
};

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

static uint64_t gcd(uint64_t a, uint64_t b)
{
	uint64_t t;

	while (b != 0)
	{
		t = b;
		b = a % b;
		a = t;
	}
	return a;
}


// Calcs. y = a^-1 mod n. (Calcs. inverse of a mod n) 
static uint64_t get_inverse(uint64_t a, uint64_t n)
{
	int64_t quotient;
	int64_t aux;
	int64_t t;
	int64_t r;
	int64_t new_r;
	int64_t new_t;

	t = 0;
	r = (int64_t) n;
	new_t = 1;
	new_r = (int64_t) a;
	while (new_r != 0)
	{
		quotient = r / new_r;

		aux = new_t;
		new_t = t - quotient * aux;
		t = aux;

		aux = new_r;
		new_r = r - quotient * aux;
		r = aux;
	}
	if (r > 1)
		return 0;
	if (t < 0)
		t += n;
	return t;
}

static void gen_private_exponent(struct s_private_key *pkey)
{
	uint64_t lambda;

	lambda = ((uint64_t) (pkey->prime_1 - 1) * (uint64_t) (pkey->prime_2 - 1)) / gcd(pkey->prime_1 - 1, pkey->prime_2 - 1);
	pkey->private_exponent = get_inverse(pkey->public_exponent, lambda);
}

static int generate_rsa_pkey(struct s_private_key *pkey, int rand_fd)
{
	if (gen_prime_32b(&(pkey->prime_1), rand_fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	if (gen_prime_32b(&(pkey->prime_2), rand_fd) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	pkey->version = 0;
	pkey->modulus = ((uint64_t) pkey->prime_1) * ((uint64_t) pkey->prime_2);
	pkey->public_exponent = GENRSA_PUBLIC_EXPONENT;
	gen_private_exponent(pkey);
	if (pkey->private_exponent == 0)
	{
		write_error("Error generating private exponent");
		return FT_SSL_FATAL_ERR;
	}
	pkey->exponent_1 = pkey->private_exponent % (pkey->prime_1 - 1);
	pkey->exponent_2 = pkey->private_exponent % (pkey->prime_2 - 1);
	pkey->coefficient = get_inverse(pkey->prime_2, pkey->prime_1);
	return FT_SSL_SUCCESS;
}

static void private_key_integrity_test(struct s_private_key *pkey)
{
	uint64_t lambda = ((uint64_t) (pkey->prime_1 - 1) * (uint64_t) (pkey->prime_2 - 1)) / gcd(pkey->prime_1 - 1, pkey->prime_2 - 1);

	if (((uint64_t) pkey->prime_1 * (uint64_t) pkey->prime_2 != pkey->modulus) \
	|| ((((__uint128_t)pkey->public_exponent * (__uint128_t)pkey->private_exponent)) % lambda) != 1 \
	|| (pkey->prime_2 * pkey->coefficient % pkey->prime_1) != 1){
		printf("Error: P %u  Q %u  P*Q %lu EXP1 %lu EXP2 %lu D %lu E %lu COEF %lu LDA %lu GCD(p-1,q-1) %lu\n", 
		pkey->prime_1, 
		pkey->prime_2, 
		pkey->modulus, 
		pkey->exponent_1, 
		pkey->exponent_2, 
		pkey->private_exponent,
		pkey->public_exponent,
		pkey->coefficient,
		lambda,
		gcd(pkey->prime_1 - 1, pkey->prime_2 - 1));
		printf("GCD(e, lambda_n) = %lu\n", gcd(pkey->public_exponent, lambda));
		printf("GCD(e, lambda_n) = %lu\n", gcd(pkey->public_exponent, lambda));
		printf("e * d mod lambda = %lu\n", (uint64_t) ((((__uint128_t)pkey->public_exponent * (__uint128_t)pkey->private_exponent)) % lambda));
		printf("q * coef mod p = %lu\n", (uint64_t) ((((__uint128_t)pkey->prime_2 * (__uint128_t)pkey->coefficient)) % pkey->prime_1));
	}
	else
		printf("Ok\n");
}

int genrsa_command(struct s_command *command, int ind, char **argv)
{
	struct s_genrsa_command genrsa;

	if (initialize_command(command, &genrsa) == FT_SSL_FATAL_ERR)
		return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	if (generate_rsa_pkey(&genrsa.pkey, genrsa.fd_rand) == FT_SSL_FATAL_ERR)
		return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	// private_key_integrity_test(&genrsa.pkey);
	return FT_SSL_SUCCESS;
}
