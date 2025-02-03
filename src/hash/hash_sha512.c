#include "ft_ssl.h"
#include "ft_hash.h"

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

static uint64_t k[80] = {
	0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
	0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
	0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
	0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
	0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
	0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
	0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
	0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
	0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
	0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
	0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
	0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
	0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
	0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817,
};

static uint64_t h_sha384[8] = {
	0xcbbb9d5dc1059ed8,
	0x629a292a367cd507,
	0x9159015a3070dd17,
	0x152fecd8f70e5939,
	0x67332667ffc00b31,
	0x8eb44a8768581511,
	0xdb0c2e0d64f98fa7,
	0x47b5481dbefa4fa4,
};

static uint64_t h_sha512[8] = {
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
};

static uint64_t h_sha512_224[8] = {
	0x8C3D37C819544DA2,
	0x73E1996689DCD4D6,
	0x1DFAB7AE32FF9C82,
	0x679DD514582F9FCF,
	0x0F6D2B697BD44DA8,
	0x77E36F7304C48942,
	0x3F9D85A86A1D36C8,
	0x1112E6AD91D692A1,
};

static uint64_t h_sha512_256[8] = {
	0x22312194FC2BF72C,
	0x9F555FA3C84C64C2,
	0x2393B86B6F53B151,
	0x963877195940EABD,
	0x96283EE2A88EFFE3,
	0xBE5E1E2553863992,
	0x2B0199FC2C85B8AA,
	0x0EB72DDC81C52CA2,
};

static int get_sha512_alg_data(struct hash_alg_data *alg, uint8_t *msg, void *h)
{
	alg->msg = msg;
	alg->msg_block_size = BITS_TO_BYTES(1024);
	alg->length_padding_size = BITS_TO_BYTES(128);
	alg->hash_values_qty = 8;
	alg->hash_values_bit_size = 64;

	if (preprocess_sha2(alg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	for (int i = 0; i < alg->hash_values_qty; i ++)
		((uint64_t *) (alg->h))[i] = ((uint64_t *) (h))[i];
	return FT_SSL_SUCCESS;
}

static uint8_t *hash(struct hash_alg_data *alg)
{
	uint64_t vars[8]; // Working variables
	uint64_t w[80]; // "Message schedule"
	uint64_t t1, t2; // Auxiliary
	uint64_t *m; // Message block
	uint64_t *hash; // Hash values
	int block_qty;

	hash = (uint64_t *) alg->h;
	block_qty = alg->padded_msg_size / alg->msg_block_size;
	for (int i = 0; i < block_qty; i++)
	{
		m = (uint64_t *) (alg->padded_msg + i * alg->msg_block_size);
		for (int j = 0; j < 8; j ++)
			vars[j] = hash[j];
		for (int j = 0; j < 16; j ++)
			w[j] = __builtin_bswap64(m[j]);
		for (int j = 16; j < 80; j ++)
			w[j] =	sigma_512_1(w[j - 2]) + w[j - 7] + sigma_512_0(w[j - 15]) + w[j - 16];
		for (int j = 0; j < 80; j ++)
		{
			t1 = vars[7] + sum_512_1(vars[4]) + ch_64b(vars[4], vars[5], vars[6]) + k[j] + w[j];
			t2 = sum_512_0(vars[0]) + maj_64b(vars[0], vars[1], vars[2]);
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
	alg->algorithm_family = ALGFAM_SHA512;
	if (get_sha512_alg_data(alg, alg->msg, h) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	alg->digest = hash(alg);
	free(alg->padded_msg);
	return FT_SSL_SUCCESS;
}

int hash_sha512(void *data)
{
	return hash_sha2((struct hash_alg_data *) data, h_sha512);
}

int hash_sha384(void *data)
{
	return hash_sha2((struct hash_alg_data *) data, h_sha384);
}

int hash_sha512_224(void *data)
{
	return hash_sha2((struct hash_alg_data *) data, h_sha512_224);
}

int hash_sha512_256(void *data)
{
	return hash_sha2((struct hash_alg_data *) data, h_sha512_256);
}
