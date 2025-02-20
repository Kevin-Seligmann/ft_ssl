#include "ft_ssl.h"
#include "ft_asym.h"

struct test_data {
	BIGNUM *s;
	BIGNUM *d;
	BIGNUM *base;
	BIGNUM *x;
	BIGNUM *y;
	BIGNUM *k;
	BIGNUM *one;
	BIGNUM *two;
	BIGNUM *num_minus_one;
	BN_CTX *ctx;
};

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

static int get_sd(BIGNUM *s, BIGNUM *d, BIGNUM *num)
{
	if (BN_copy(d, num) == 0)
		return -1;
	if (BN_sub_word(d, 1) == 0)
		return -1;
	if (BN_set_word(s, 0) == 0)
		return -1;
	while (!BN_is_odd(d))
	{
		if (BN_rshift1(d, d) == 0)
			return -1;
		if (BN_add_word(s, 1) == 0)
			return -1;
	}
	return 0;
}

static int primality_test(BIGNUM *num, int rand_fd, uint32_t rounds, struct test_data *data)
{
	if (BN_copy(data->num_minus_one, num) == 0)
		return -1;
	if (BN_sub_word(data->num_minus_one, 1) == 0)
		return -1;
	if (get_sd(data->s, data->d, num) == -1)
		return -1;
	for (uint32_t i = 0; i < rounds; i ++)
	{
		if (BN_set_word(data->base, 0) == 0)
			return -1;
		if (BN_rand(data->base, KEY_BIT_SIZE - 1, -1, -1) == 0)
			return -1;
		if (BN_mod_exp(data->x, data->base, data->d, num, data->ctx) == 0)
			return -1;
		if (BN_set_word(data->k, 0) == 0)
			return -1;
		while (BN_cmp(data->k, data->s) == -1)
		{
			if (BN_mod_exp(data->y, data->x, data->two, num, data->ctx) == 0)
				return -1;
			if (BN_cmp(data->y, data->one) == 0 && BN_cmp(data->x, data->one) != 0 && BN_cmp(data->x, data->num_minus_one) != 0)
				return 0;
			if (BN_copy(data->x, data->y) == 0)
				return -1;
			if (BN_add_word(data->k, 1) == 0)
				return -1;
		}
		if (BN_cmp(data->y, data->one) != 0)
			return 0;
	}
	return 1;
}

static int exit_test(int ret, struct test_data *data)
{
	BN_CTX_free(data->ctx);
	BN_free(data->s);
	BN_free(data->d);
	BN_free(data->base);
	BN_free(data->x);
	BN_free(data->y);
	BN_free(data->k);
	BN_free(data->one);
	BN_free(data->two);
	BN_free(data->num_minus_one);
	return ret;
}

static int init_test_bigints(struct test_data *data)
{
	data->ctx = BN_CTX_new();
	data->s = BN_new();
	data->d = BN_new();
	data->base = BN_new();
	data->x = BN_new();
	data->y = BN_new();
	data->k = BN_new();
	data->one = BN_new();
	data->two = BN_new();
	data->num_minus_one = BN_new();

	if (
		data->ctx == 0 || \
		data->s == 0 || \
		data->d == 0 || \
		data->base == 0 || \
		data->x == 0 || \
		data->y == 0 || \
		data->k == 0 || \
		data->one == 0 || \
		data->two == 0 || \
		data->num_minus_one == 0 || \
		BN_set_word(data->one, 1) == 0 || \
		BN_set_word(data->two, 2) == 0
	)
		return FT_SSL_FATAL_ERR;
	return FT_SSL_SUCCESS;
}

int gen_prime(BIGNUM **prime, int rand_fd)
{
	int ret;
	uint32_t rounds;
	struct test_data data;

	get_rounds(&rounds, GENRSA_PRIMALITY_ACCURACY);
	if (init_test_bigints(&data) == FT_SSL_FATAL_ERR)
		return exit_test(FT_SSL_FATAL_ERR, &data);
	while (1)
	{
		BN_rand(*prime, KEY_BIT_SIZE / 2, 1, 1);
		ret = primality_test(*prime, rand_fd, rounds, &data);
		if (ret == -1)
			return exit_test(FT_SSL_FATAL_ERR, &data);
		if (ret == 1)
			break ;
	}
	return exit_test(FT_SSL_SUCCESS, &data);
}
