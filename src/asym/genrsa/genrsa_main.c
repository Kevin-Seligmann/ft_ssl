#include "ft_ssl.h"
#include "ft_asym.h"

struct s_private_key {
	uint64_t version;
	uint64_t modulus;
	uint64_t public_exponent;
	uint64_t private_exponent;
	uint64_t prime_1;
	uint64_t prime_2;
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
	genrsa->pkey.version = 0;
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

static int test_prime_32b(uint32_t candidate)
{

}

static void gen_prime_32b(uint32_t *prime, int rand_fd)
{
	uint32_t candidate;

	while (1)
	{
		read(rand_fd, &candidate, 32 / 8);
		if (test_prime_32b(candidate))
			return ;
	}
}

static void generate_rsa_pkey(struct s_private_key *pkey, int rand_fd)
{
	gen_prime_32b((uint32_t *) &(pkey->prime_1), rand_fd);
	gen_prime_32b((uint32_t *) &(pkey->prime_2), rand_fd);
	pkey->modulus = pkey->prime_1 * pkey->prime_2;
}

int genrsa_command(struct s_command *command, int ind, char **argv)
{
	struct s_genrsa_command genrsa;

	if (initialize_command(command, &genrsa) == FT_SSL_FATAL_ERR)
		return exit_command(&genrsa, FT_SSL_FATAL_ERR);
	generate_rsa_pkey(&genrsa.pkey, genrsa.fd_rand);
	return FT_SSL_SUCCESS;
}
