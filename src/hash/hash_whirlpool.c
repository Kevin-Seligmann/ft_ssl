#include "ft_ssl.h"
#include "ft_hash.h"

# define MAT(row, col, rowsize) (col + row * rowsize)

// https://www2.seas.gwu.edu/~poorvi/Classes/CS381_2007/Whirlpool.pdf

static uint8_t sbox[16 * 16] = {
	0x18, 0x23, 0xc6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xd2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 
	0x60, 0xBc, 0x9B, 0x8E, 0xA3, 0x0c, 0x7B, 0x35, 0x1d, 0xE0, 0xd7, 0xc2, 0x2E, 0x4B, 0xFE, 0x57, 
	0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xdA, 0x58, 0xc9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85, 
	0xBd, 0x5d, 0x10, 0xF4, 0xcB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7d, 0x95, 0xd8, 
	0xFB, 0xEE, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9E, 0xcA, 0x2d, 0xBF, 0x07, 0xAd, 0x5A, 0x83, 0x33, 
	0x63, 0x02, 0xAA, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0, 
	0xE9, 0x0F, 0xd5, 0x80, 0xBE, 0xcd, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE, 
	0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xEc, 0xdB, 0xA1, 0x8d, 0x3d, 
	0x97, 0x00, 0xcF, 0x2B, 0x76, 0x82, 0xd6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF, 
	0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xc0, 0xdE, 0x1c, 0xFd, 0x4d, 0x92, 0x75, 0x06, 0x8A, 
	0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xd4, 0xA8, 0x96, 0xF9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c, 
	0x5E, 0x78, 0x38, 0x8c, 0xd1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9c, 0x1E, 0x43, 0xc7, 0xFc, 0x04, 
	0x51, 0x99, 0x6d, 0x0d, 0xFA, 0xdF, 0x7E, 0x24, 0x3B, 0xAB, 0xcE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB, 
	0x3c, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2c, 0xd3, 0xE7, 0x6E, 0xc4, 0x03, 0x56, 0x44, 0x7F, 0xA9, 
	0x2A, 0xBB, 0xc1, 0x53, 0xdc, 0x0B, 0x9d, 0x6c, 0x31, 0x74, 0xF6, 0x46, 0xAc, 0x89, 0x14, 0xE1, 
	0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xd0, 0xEd, 0xcc, 0x42, 0x98, 0xA4, 0x28, 0x5c, 0xF8, 0x86, 
};

static uint8_t c_transformation[64] = {
	0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09,
	0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02,
	0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05,
	0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08,
	0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01,
	0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04,
	0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01,
	0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01,
};

static uint8_t rc_box[64] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

static uint8_t gf_mul_table[256][256];

static uint8_t gf_mul(uint8_t a, uint8_t b) {
	uint8_t result = 0;
	while (b) {
		if (b & 1) 
			result ^= a;
		a = (a << 1) ^ (a & 0x80 ? 0x11D : 0x00); 
		b >>= 1;
	}
	return result;
}

void init_gf_mul_table() {
	for (int i = 0; i < 256; i++) {
		for (int j = 0; j < 256; j++) {
			gf_mul_table[i][j] = gf_mul(i, j);
		}
	}
}

static int get_whirlpool_data(struct hash_alg_data *alg, uint8_t *msg)
{
	alg->msg = msg;
	alg->msg_block_size = BITS_TO_BYTES(512);
	alg->length_padding_size = BITS_TO_BYTES(256);
	alg->hash_values_qty = 64;
	alg->hash_values_bit_size = 8;

	if (preprocess_whirlpool(alg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	for (int i = 0; i < alg->hash_values_qty; i ++)
		((uint8_t *) (alg->h))[i] = 0;
	return FT_SSL_SUCCESS;
}

static void mat_xor(uint8_t *dest, uint8_t *r1, uint8_t *r2, int rows, int cols)
{
	for (int i = 0; i < rows; i ++)
		for (int j = 0; j < cols; j ++)
			dest[MAT(i, j, rows)] = r1[MAT(i, j, rows)] ^ r2[MAT(i, j, rows)];
}

static void mat_xor_inplace(uint8_t *r1, uint8_t *r2, int rows, int cols)
{
	for (int i = 0; i < rows; i ++)
		for (int j = 0; j < cols; j ++)
			r1[MAT(i, j, rows)] ^= r2[MAT(i, j, rows)];
}

static void mat_cpy(uint8_t *dest, uint8_t *r1, int rows, int cols)
{
	for (int i = 0; i < rows; i ++)
		for (int j = 0; j < cols; j ++)
			dest[MAT(i, j, rows)] = r1[MAT(i, j, rows)];
}

void add_key(uint8_t *mat, uint8_t *key)
{
	mat_xor_inplace(mat, key, 8, 8);
}

void add_round_const(uint8_t *key, int round)
{
	for (int j = 0; j < 8; j ++)
		rc_box[MAT(0, j, 8)] = sbox[8 * round + j];
	mat_xor_inplace(key, rc_box, 8, 8);
}


void substitute_bytes(uint8_t *mat)
{
	int sbox_row;
	int sbox_col;

	for (int i = 0; i < 8; i ++)
	{
		for (int j = 0; j < 8; j ++)
		{
			sbox_row = (mat[MAT(i ,j, 8)] >> 4) & 0xF;
			sbox_col = (mat[MAT(i ,j, 8)]) & 0xF;
			mat[MAT(i ,j, 8)] = sbox[MAT(sbox_row, sbox_col, 16)];
		}	
	}
}

void shift_columns(uint8_t *mat)
{
	uint8_t aux[64];

	for (int i = 0; i < 8; i ++)
	{
		for (int j = 0; j < 8; j ++)
		{
			aux[MAT(i, j, 8)] = mat[MAT((i - j + 8) % 8, j, 8)];
		}	
	}
	mat_cpy(mat, aux, 8, 8);
}

void mix_rows(uint8_t *mat)
{
	uint8_t aux[64];

	for (int i = 0; i < 8; i ++)
	{
		for (int j = 0; j < 8; j ++)
		{
			aux[MAT(i, j, 8)] = 0;
			for (int k = 0; k < 8; k ++)
			{
				aux[MAT(i, j, 8)] ^= gf_mul_table[mat[MAT(i, k, 8)]][c_transformation[MAT(k, j, 8)]];
			}
		}
	}
	mat_cpy(mat, aux, 8, 8);
}

static void wcypher(uint8_t *wbuffer, uint8_t *key, uint8_t *plaintext)
{
	uint8_t kbuffer[64];

	mat_cpy(wbuffer, plaintext, 8, 8);	// Wbuffer will be the result
	mat_cpy(kbuffer, key, 8, 8);		// Key is the H state, don't want to modify it.

	add_key(wbuffer, kbuffer);
	for (int i = 0; i < 10; i ++)
	{
		substitute_bytes(kbuffer);
		shift_columns(kbuffer);
		mix_rows(kbuffer);
		add_round_const(kbuffer, i);

		substitute_bytes(wbuffer);
		shift_columns(wbuffer);
		mix_rows(wbuffer);
		add_key(wbuffer, kbuffer);
	}
}

static uint8_t *hash(struct hash_alg_data *alg)
{
	uint8_t *m;
	uint8_t *h;
	uint8_t aux[64];
	uint8_t cyper_block[64];
	int block_qty;

	h = (uint8_t *) alg->h;
	block_qty = alg->padded_msg_size / alg->msg_block_size;
	init_gf_mul_table();
	for (int i = 0; i < block_qty; i++)
	{
		m = alg->padded_msg + i * alg->msg_block_size;
		wcypher(cyper_block, h, m);
		mat_xor_inplace(cyper_block, h, 8, 8);
		mat_xor_inplace(cyper_block, m, 8, 8);
		mat_cpy(h, cyper_block, 8, 8);
	}
	return h;
}

int hash_whirlpool(void *data)
{
	struct hash_alg_data *alg;

	alg = (struct hash_alg_data *) data;
	alg->algorithm_family = ALGFAM_WHIRLPOOL;
	if (get_whirlpool_data(alg, alg->msg) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	alg->digest = hash(alg);
	free(alg->padded_msg);
	return FT_SSL_SUCCESS;
}
