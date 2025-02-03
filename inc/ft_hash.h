#ifndef FT_HASH_H

# define FT_HASH_H

# define BITS_TO_BYTES(x) ((x) / 8)

# define ALGFAM_MD5 1
# define ALGFAM_WHIRLPOOL 2
# define ALGFAM_SHA256 3
# define ALGFAM_SHA512 4

struct hash_alg_data {
	int algorithm_family;
	uint8_t *msg; // Original message
	uint8_t *padded_msg; // Buffer for the padded message
	size_t padded_msg_size; // Size of the padded message
	int length_padding_size; // Messages are padded with length of 64 bits, 128 bits or 256 sizes.
	int msg_block_size; // The original message is digested on chunks of this size
	void *h; // Hash initial values
	int hash_values_qty; // How many words
	int hash_values_bit_size;  // Size of words (32 or 64 bits)
	uint8_t *digest; // Be aware of this and h being the same pointer. (H keept separated if want to incorporate chunk hashing and clarity)
};

void print_command_result(struct s_command *command, uint8_t *digest, char *src, int print_type);

int preprocess_sha2(struct hash_alg_data *alg);
int preprocess_md5(struct hash_alg_data *alg);
int preprocess_whirlpool(struct hash_alg_data *alg);

// 256 family operators
uint32_t ch_32b(uint32_t x, uint32_t y, uint32_t z);
uint32_t maj_32b(uint32_t x, uint32_t y, uint32_t z);
uint32_t sum_256_0(uint32_t x);
uint32_t sum_256_1(uint32_t x);
uint32_t sigma_256_0(uint32_t x);
uint32_t sigma_256_1(uint32_t x);

// 512 family operators
uint64_t ch_64b(uint64_t x, uint64_t y, uint64_t z);
uint64_t maj_64b(uint64_t x, uint64_t y, uint64_t z);
uint64_t sum_512_0(uint64_t x);
uint64_t sum_512_1(uint64_t x);
uint64_t sigma_512_0(uint64_t x);
uint64_t sigma_512_1(uint64_t x);

#endif
