#ifndef FT_ENCRYPTION_H

# define FT_ENCRYPTION_H

// Algorithms
# define SIM_ENC_ALG_DES_ECB 0x1
# define SIM_ENC_ALG_DES_CBC 0x2
# define SIM_ENC_ALG_DES_PCBC 0x4
# define SIM_ENC_ALG_DES_CFB 0x8
# define SIM_ENC_ALG_DES_OFB 0x40
# define SIM_ENC_ALG_DES_CTR 0x80
# define SIM_ENC_ALG_DES_EDE_ECB 0x100
# define SIM_ENC_ALG_DES_EDE_CBC 0x200
# define SIM_ENC_ALG_DES_EDE_PCBC 0x400
# define SIM_ENC_ALG_DES_EDE_CFB 0x800
# define SIM_ENC_ALG_DES_EDE_OFB 0x4000
# define SIM_ENC_ALG_DES_EDE_CTR 0x8000
# define SIM_ENC_ALG_DES_EDE3_ECB 0x10000
# define SIM_ENC_ALG_DES_EDE3_CBC 0x20000
# define SIM_ENC_ALG_DES_EDE3_PCBC 0x40000
# define SIM_ENC_ALG_DES_EDE3_CFB 0x80000
# define SIM_ENC_ALG_DES_EDE3_OFB 0x400000
# define SIM_ENC_ALG_DES_EDE3_CTR 0x800000

// Constants
# define CIPHER_BLOCK_SIZE (64 / 8)
# define SINGLE_DES_KEYLEN (64 / 8)
# define DES_SALT_LENGTH (64 / 8)
# define DES_IV_LENGTH (64 / 8)
# define DES_RIGHTSIDE_EXPANSION_LENGTH (16 / 2)
# define DES_ROUND_COUNT 16

// DES Type
# define DES 0x1
# define DES_EDE 0x2
# define DES_EDE3 0x4

// Cipher block type
# define ECB_MODE 1
# define CBC_MODE 2
# define PCBC_MODE 3
# define CFB_MODE 4
# define OFB_MODE 5
# define CTR_MODE 6

// Encryption request
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

// Internal functions
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
int print_debug_info(struct s_command *command, struct s_encryption *data);

// Encryption functions
int encryption_command(struct s_command *command, int ind, char **argv);
int des_ecb_command(void *data);
int des_cbc_command(void *data);
int des_pcbc_command(void *data);
int des_ofb_command(void *data);
int des_cfb_command(void *data);
int des_ctr_command(void *data);
int des_ede_ecb_command(void *data);
int des_ede_cbc_command(void *data);
int des_ede_pcbc_command(void *data);
int des_ede_cfb_command(void *data);
int des_ede_ofb_command(void *data);
int des_ede_ctr_command(void *data);
int des_ede3_ecb_command(void *data);
int des_ede3_cbc_command(void *data);
int des_ede3_pcbc_command(void *data);
int des_ede3_cfb_command(void *data);
int des_ede3_ofb_command(void *data);
int des_ede3_ctr_command(void *data);

#endif
