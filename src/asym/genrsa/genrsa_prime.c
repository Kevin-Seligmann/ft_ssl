#include "ft_ssl.h"
#include "ft_asym.h"

static void get_rounds(uint32_t *rounds, double prime_probability)
{
	double liar_probability;
	double e;
	uint32_t k;

	/*
		probability is that a given candidate is not prime: l = 1 / (4)^k.
		Find k such that l < liar_probability;
		if... l < liar_probability
		1 / (4)^k < liar_probability
		liar_probability * (4)^k > 1
		e = (4)^k
	*/

	liar_probability = 1 - prime_probability;
	k = 0;
	e = 1;
	while (liar_probability * e < 1)
	{
		e *= 4;
		k ++;
	}
	*rounds = k;
}

static void get_sd(uint32_t *s, uint32_t *d, uint32_t n)
{
	uint32_t exponent;

	exponent = 0;
	while (IS_EVEN(n))
	{
		n >>= 1;
		exponent ++;
	}
	*d = n;
	*s = exponent;
}

static uint32_t mod_exp(uint32_t b, uint32_t e, uint32_t m)
{
	uint32_t c;

	c = 1;
	b = b % m;
	while (e > 0)
	{
		if (!IS_EVEN(e))
			c = (((uint64_t) c) * ((uint64_t) b)) % m;
		e >>= 1;
		b = (((uint64_t) b) * ((uint64_t) b)) % m;
	}
	return c;
}

static int primality_test(uint32_t candidate, int rand_fd, uint32_t rounds)
{
	uint32_t s;
	uint32_t d;
	uint32_t base;
	uint32_t x;
	uint32_t y;

	get_sd(&s, &d, candidate - 1);
	for (uint32_t i = 0; i < rounds; i ++)
	{
		base = 0;
		while (base < 2)
		if (read(rand_fd, &base, sizeof(base)) != sizeof(base))
			return -1;
		if (base > candidate - 2)
			base = base % candidate - 2;
		x = mod_exp(base, d, candidate);
		for (uint32_t k = 0; k < s; k ++)
		{
			y = mod_exp(x, 2, candidate);
			if (y == 1 && x != 1 && x != candidate - 1)
				return 0;
			x = y;
		}
		if (y != 1)
			return 0;
	}
	return 1;
}

int gen_prime_32b(uint32_t *prime, int rand_fd)
{
	int ret;
	uint32_t candidate;
	uint32_t rounds;

	get_rounds(&rounds, GENRSA_PRIMALITY_ACCURACY);
	while (1)
	{
		read(rand_fd, &candidate, 32 / 8);
		candidate |= 0x80000001;
		ret = primality_test(candidate, rand_fd, rounds);
		if (ret == -1)
		{
			write_error2("Error reading file /dev/urandom", strerror(errno));
			return FT_SSL_FATAL_ERR;
		}
		if (ret == 1)
			break ;
	}
	*prime = candidate;
	return FT_SSL_SUCCESS;
}
