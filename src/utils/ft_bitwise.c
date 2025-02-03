#include "ft_ssl.h"

void do_permutation_32b(uint32_t *buffer, char permutation[32])
{
	uint32_t aux;

	aux = 0;
	for (int i = 0; i < 32; i++)
	{
		aux <<= 1;
		aux |= ((*buffer) >> (32 - permutation[i])) & 0x1;
	}
	*buffer = aux;
}

void do_permutation_56b(uint64_t *key, char permutation[56])
{
	uint64_t aux;

	aux = 0;
	for (int i = 0; i < 56; i++)
	{
		aux <<= 1;
		aux |= ((*key) >> (64 - permutation[i])) & 0x1;
	}
	*key = aux;
}
