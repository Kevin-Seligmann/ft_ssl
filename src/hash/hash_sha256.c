#include "ft_ssl.h"
#include "ft_hash.h"

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

static uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t h_sha224[8] = {
	0xc1059ed8,
	0x367cd507,
	0x3070dd17,
	0xf70e5939,
	0xffc00b31,
	0x68581511,
	0x64f98fa7,
	0xbefa4fa4,
};

static uint32_t h_sha256[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
};

static int get_sha256_alg_data(struct hash_alg_data *alg, uint8_t *msg, void *h)
{
	alg->msg = msg;
	alg->msg_block_size = BITS_TO_BYTES(512);
	alg->length_padding_size = BITS_TO_BYTES(64);
	alg->hash_values_qty = 8;
	alg->hash_values_bit_size = 32;
	
	if (preprocess_sha2(alg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	for (int i = 0; i < alg->hash_values_qty; i ++)
		((uint32_t *) (alg->h))[i] = ((uint32_t *) (h))[i];
	return FT_SSL_SUCCESS;
}

static uint8_t *hash(struct hash_alg_data *alg)
{
	uint32_t vars[8]; // Working variables
	uint32_t w[64]; // "Message schedule"
	uint32_t t1, t2; // Auxiliary
	uint32_t *m; // Message block
	uint32_t *hash; // Hash values
	int block_qty;

	hash = (uint32_t *) alg->h;
	block_qty = alg->padded_msg_size / alg->msg_block_size;
	for (int i = 0; i < block_qty; i++)
	{
		m = (uint32_t *) (alg->padded_msg + i * alg->msg_block_size);
		for (int j = 0; j < 8; j ++)
			vars[j] = hash[j];
		for (int j = 0; j < 16; j ++)
			w[j] = __builtin_bswap32(m[j]);
		for (int j = 16; j < 64; j ++)
			w[j] =	sigma_256_1(w[j - 2]) + w[j - 7] + sigma_256_0(w[j - 15]) + w[j - 16];
		for (int j = 0; j < 64; j ++)
		{
			t1 = vars[7] + sum_256_1(vars[4]) + ch_32b(vars[4], vars[5], vars[6]) + k[j] + w[j];
			t2 = sum_256_0(vars[0]) + maj_32b(vars[0], vars[1], vars[2]);
			vars[7] = vars[6];
			vars[6] = vars[5];
			vars[5] = vars[4];
			vars[4] = vars[3] + t1;
			vars[3] = vars[2];
			vars[2] = vars[1];
			vars[1] = vars[0];
			vars[0] = t1 + t2;
		}
		for (int j = 0; j < 8; j ++)
			hash[j] += vars[j];
	}
	return (uint8_t *) hash;
}

static int hash_sha2(struct hash_alg_data *alg, void *h)
{
	alg->algorithm_family = ALGFAM_SHA256;
	if (get_sha256_alg_data(alg, alg->msg, h) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	alg->digest = hash(alg);
	free(alg->padded_msg);
	return FT_SSL_SUCCESS;
}

int hash_sha224(void *data)
{
	return hash_sha2(data, h_sha224);
}

int hash_sha256(void *data)
{
	return hash_sha2(data, h_sha256);
}
