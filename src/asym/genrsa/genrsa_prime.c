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

static void get_sd(BIGNUM *s, BIGNUM *d, BIGNUM *num)
{
	BN_copy(d, num);
	BN_sub_word(d, 1);
	BN_set_word(s, 0);
	while (!BN_is_odd(d))
	{
		BN_rshift1(d, d);
		BN_add_word(s, 1);
	}
}

static int primality_test(BIGNUM *num, int rand_fd, uint32_t rounds)
{
	BIGNUM *s;
	BIGNUM *d;
	BIGNUM *base;
	BIGNUM *x;
	BIGNUM *y;
	BIGNUM *k;
	BIGNUM *one;
	BIGNUM *two;
	BIGNUM *num_minus_one;
	BN_CTX *ctx1;
	BN_CTX *ctx2;

	ctx1 = BN_CTX_new();
	ctx2 = BN_CTX_new();
	s = BN_new();
	d = BN_new();
	base = BN_new();
	x = BN_new();
	y = BN_new();
	k = BN_new();
	one = BN_new();
	two = BN_new();
	num_minus_one = BN_dup(num);
	BN_sub_word(num_minus_one, 1);
	BN_set_word(one, 1);
	BN_set_word(two, 2);
	get_sd(s, d, num);
	for (uint32_t i = 0; i < rounds; i ++)
	{
		BN_set_word(base, 0);
//		while (base < 2)
//			if (read(rand_fd, &base, sizeof(base)) != sizeof(base))
//				return -1;
		BN_rand(base, KEY_BIT_SIZE - 1, -1, -1);
		BN_mod_exp(x, base, d, num, ctx1);
		BN_set_word(k, 0);
		while (BN_cmp(k, s) == -1)
		{
			BN_mod_exp(y, x, two, num, ctx2);
			if (BN_cmp(y, one) == 0 && BN_cmp(x, one) != 0 && BN_cmp(x, num_minus_one) != 0)
				return 0;
			BN_copy(x, y);
			BN_add_word(k, 1);
		}
		if (BN_cmp(y, one) != 0)
			return 0;
	}
	return 1;
}

int gen_prime(BIGNUM **prime, int rand_fd)
{
	int ret;
	uint32_t rounds;

	get_rounds(&rounds, GENRSA_PRIMALITY_ACCURACY);
	*prime = BN_new();
	while (1)
	{
		//read(rand_fd, &candidate, 32 / 8);
		//candidate |= 0x80000001;
		BN_rand(*prime, KEY_BIT_SIZE / 2, 1, 1);
		ret = primality_test(*prime, rand_fd, rounds);
		if (ret == -1)
		{
			write_error2("Error reading file /dev/urandom", strerror(errno));
			return FT_SSL_FATAL_ERR;
		}
		if (ret == 1)
			break ;
	}
	return FT_SSL_SUCCESS;
}
