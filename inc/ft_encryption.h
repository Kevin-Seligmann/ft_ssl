#ifndef FT_ENCRYPTION_H

# define FT_ENCRYPTION_H

# define DES 0x1
# define DES_EDE 0x2
# define DES_EDE3 0x4
# define CIPHER_BLOCK_SIZE (64 / 8)
# define SINGLE_DES_KEYLEN (64 / 8)
# define DES_SALT_LENGTH (64 / 8)
# define DES_IV_LENGTH (64 / 8)
# define DES_RIGHTSIDE_EXPANSION_LENGTH (16 / 2)
# define DES_ROUND_COUNT 16

# define ECB_MODE 1
# define CBC_MODE 2
# define PCBC_MODE 3
# define CFB_MODE 4
# define OFB_MODE 5
# define CTR_MODE 6

	struct s_encryption {
		int flags;
		int encryption_mode;
		int cipher_mode;
		int key_length;
		int salt_length;
		int iv_length;
		size_t input_length;
		size_t output_length;
		char *ksiv_buffer; // Key, salt, vector.
		char *source_buffer;
		char *result_buffer;
		char *encoded_result_buffer;
		char *decoded_source_buffer;
		char *previous_ciphertext;
		char *previous_plaintext;
		uint64_t keys[DES_ROUND_COUNT];
	};

int	get_keys(struct s_command *command, struct s_encryption *data);
void copy_w_truncation_or_padding(char *dest, char *source, size_t dest_len, size_t source_len);
void copy_hexa(uint8_t *dest, char *source, size_t dest_len, size_t source_len);
int get_key_length(unsigned int encryption_mode);
int get_encryption_mode(unsigned int alg);
int get_cipher_mode(unsigned int alg);
int get_initialization_vector(struct s_command *command, struct s_encryption *data);
int get_text_to_transform(struct s_command *command, struct s_encryption *data);
int encode_ciphertext_base64(struct s_command *command, struct s_encryption *data);
int decode_ciphertext_base64(struct s_command *command, struct s_encryption *data);
int get_salt(struct s_command *command, struct s_encryption *data);
int output_encryption_result(struct s_command *command, struct s_encryption *data);
int is_hexa(char *str, size_t size);
uint64_t stohex(char *str);

void process_block(uint64_t input, uint64_t *output, uint64_t keys[DES_ROUND_COUNT], int mode);
void generate_key_schedule(uint64_t *key, uint64_t keys[DES_ROUND_COUNT]);

#endif
