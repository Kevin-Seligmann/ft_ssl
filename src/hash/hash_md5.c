#include "ft_ssl.h"
#include "ft_hash.h"
#include "ft_bitwise.h"

// https://www.ietf.org/rfc/rfc1321.txt

#define F(x, y, z) ((x & y) | ((~x) & z))
#define G(x, y, z) ((x & z) | (y & (~z)))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | (~z)))

#define OPE1(a, b, c, d, x, y, z) (a = (b + (ROTATE_LEFT_32B((a + (F(b,c,d) + (m[x] + k[z - 1]))), y))))
#define OPE2(a, b, c, d, x, y, z) (a = (b + (ROTATE_LEFT_32B((a + (G(b,c,d) + (m[x] + k[z - 1]))), y))))
#define OPE3(a, b, c, d, x, y, z) (a = (b + (ROTATE_LEFT_32B((a + (H(b,c,d) + (m[x] + k[z - 1]))), y))))
#define OPE4(a, b, c, d, x, y, z) (a = (b + (ROTATE_LEFT_32B((a + (I(b,c,d) + (m[x] + k[z - 1]))), y))))

static uint32_t h_md5[4] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
};

static uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static int get_md5_data(struct hash_alg_data *alg, uint8_t *msg)
{
	alg->msg = msg;
	alg->msg_block_size = BITS_TO_BYTES(512);
	alg->length_padding_size = BITS_TO_BYTES(64);
	alg->hash_values_qty = 4;
	alg->hash_values_bit_size = 32;

	if (preprocess_md5(alg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	for (int i = 0; i < alg->hash_values_qty; i ++)
		((uint32_t *) (alg->h))[i] = ((uint32_t *) (h_md5))[i];
	return FT_SSL_SUCCESS;
}

static uint8_t *hash(struct hash_alg_data *alg)
{
	uint32_t vars[4]; // Working variables
	uint32_t *m; // Message block
	uint32_t *h; // Hash values
	int block_qty;

	h = (uint32_t *) alg->h;
	block_qty = alg->padded_msg_size / alg->msg_block_size;
	for (int i = 0; i < block_qty; i++)
	{
		m = (uint32_t *) (alg->padded_msg + i * alg->msg_block_size);

		for (int j = 0; j < 4; j ++)
		 	vars[j] = h[j];

		OPE1(vars[0], vars[1], vars[2], vars[3], 0, 7, 1);
		OPE1(vars[3], vars[0], vars[1], vars[2], 1, 12, 2);
		OPE1(vars[2], vars[3], vars[0], vars[1], 2, 17, 3);
		OPE1(vars[1], vars[2], vars[3], vars[0], 3, 22, 4);

		OPE1(vars[0], vars[1], vars[2], vars[3], 4, 7, 5);
		OPE1(vars[3], vars[0], vars[1], vars[2], 5, 12, 6);
		OPE1(vars[2], vars[3], vars[0], vars[1], 6, 17, 7);
		OPE1(vars[1], vars[2], vars[3], vars[0], 7, 22, 8);

		OPE1(vars[0], vars[1], vars[2], vars[3], 8, 7, 9);
		OPE1(vars[3], vars[0], vars[1], vars[2], 9, 12, 10);
		OPE1(vars[2], vars[3], vars[0], vars[1], 10, 17, 11);
		OPE1(vars[1], vars[2], vars[3], vars[0], 11, 22, 12);

		OPE1(vars[0], vars[1], vars[2], vars[3], 12, 7, 13);
		OPE1(vars[3], vars[0], vars[1], vars[2], 13, 12, 14);
		OPE1(vars[2], vars[3], vars[0], vars[1], 14, 17, 15);
		OPE1(vars[1], vars[2], vars[3], vars[0], 15, 22, 16);

		// Round 17-32
		OPE2(vars[0], vars[1], vars[2], vars[3], 1, 5, 17);
		OPE2(vars[3], vars[0], vars[1], vars[2], 6, 9, 18);
		OPE2(vars[2], vars[3], vars[0], vars[1], 11, 14, 19);
		OPE2(vars[1], vars[2], vars[3], vars[0], 0, 20, 20);

		OPE2(vars[0], vars[1], vars[2], vars[3], 5, 5, 21);
		OPE2(vars[3], vars[0], vars[1], vars[2], 10, 9, 22);
		OPE2(vars[2], vars[3], vars[0], vars[1], 15, 14, 23);
		OPE2(vars[1], vars[2], vars[3], vars[0], 4, 20, 24);

		OPE2(vars[0], vars[1], vars[2], vars[3], 9, 5, 25);
		OPE2(vars[3], vars[0], vars[1], vars[2], 14, 9, 26);
		OPE2(vars[2], vars[3], vars[0], vars[1], 3, 14, 27);
		OPE2(vars[1], vars[2], vars[3], vars[0], 8, 20, 28);
		
		OPE2(vars[0], vars[1], vars[2], vars[3], 13, 5, 29);
		OPE2(vars[3], vars[0], vars[1], vars[2], 2, 9, 30);
		OPE2(vars[2], vars[3], vars[0], vars[1], 7, 14, 31);
		OPE2(vars[1], vars[2], vars[3], vars[0], 12, 20, 32);

		
		// Round 33-48
		OPE3(vars[0], vars[1], vars[2], vars[3], 5, 4, 33);
		OPE3(vars[3], vars[0], vars[1], vars[2], 8, 11, 34);
		OPE3(vars[2], vars[3], vars[0], vars[1], 11, 16, 35);
		OPE3(vars[1], vars[2], vars[3], vars[0], 14, 23, 36);

		OPE3(vars[0], vars[1], vars[2], vars[3], 1, 4, 37);
		OPE3(vars[3], vars[0], vars[1], vars[2], 4, 11, 38);
		OPE3(vars[2], vars[3], vars[0], vars[1], 7, 16, 39);
		OPE3(vars[1], vars[2], vars[3], vars[0], 10, 23, 40);

		OPE3(vars[0], vars[1], vars[2], vars[3], 13, 4, 41);
		OPE3(vars[3], vars[0], vars[1], vars[2], 0, 11, 42);
		OPE3(vars[2], vars[3], vars[0], vars[1], 3, 16, 43);
		OPE3(vars[1], vars[2], vars[3], vars[0], 6, 23, 44);

		OPE3(vars[0], vars[1], vars[2], vars[3], 9, 4, 45);
		OPE3(vars[3], vars[0], vars[1], vars[2], 12, 11, 46);
		OPE3(vars[2], vars[3], vars[0], vars[1], 15, 16, 47);
		OPE3(vars[1], vars[2], vars[3], vars[0], 2, 23, 48);
		
		// Round 49-64
		OPE4(vars[0], vars[1], vars[2], vars[3], 0, 6, 49);
		OPE4(vars[3], vars[0], vars[1], vars[2], 7, 10, 50);
		OPE4(vars[2], vars[3], vars[0], vars[1], 14, 15, 51);
		OPE4(vars[1], vars[2], vars[3], vars[0], 5, 21, 52);

		OPE4(vars[0], vars[1], vars[2], vars[3], 12, 6, 53);
		OPE4(vars[3], vars[0], vars[1], vars[2], 3, 10, 54);
		OPE4(vars[2], vars[3], vars[0], vars[1], 10, 15, 55);
		OPE4(vars[1], vars[2], vars[3], vars[0], 1, 21, 56);

		OPE4(vars[0], vars[1], vars[2], vars[3], 8, 6, 57);
		OPE4(vars[3], vars[0], vars[1], vars[2], 15, 10, 58);
		OPE4(vars[2], vars[3], vars[0], vars[1], 6, 15, 59);
		OPE4(vars[1], vars[2], vars[3], vars[0], 13, 21, 60);

		OPE4(vars[0], vars[1], vars[2], vars[3], 4, 6, 61);
		OPE4(vars[3], vars[0], vars[1], vars[2], 11, 10, 62);
		OPE4(vars[2], vars[3], vars[0], vars[1], 2, 15, 63);
		OPE4(vars[1], vars[2], vars[3], vars[0], 9, 21, 64);

		for (int j = 0; j < 4; j ++)
			h[j] += vars[j];
	}
	return (uint8_t *) h;
}

int hash_md5(void *data)
{
	struct hash_alg_data *alg;

	alg = (struct hash_alg_data *) data;
	alg->algorithm_family = ALGFAM_MD5;
	if (get_md5_data(alg, alg->msg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	alg->digest = hash(alg);
	free(alg->padded_msg);
	return FT_SSL_SUCCESS;
}
