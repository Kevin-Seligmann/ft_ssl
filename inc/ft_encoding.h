#ifndef FT_ENCODING_H

# define FT_ENCODING_H

struct s_encoding {
	int flags;
	char *input;
	char *output;
	size_t input_size;
	size_t output_size;
};

// Types of encoding algorithms
# define ENC_ALG_BASE64 0x01
# define DEC_ALG_BASE64 0x02

# define BASE64_PAD_BYTE '='
# define BASE64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
# define BASE64_WHITESPACE " \n"
# define BYTE_00110000 0x30
# define BYTE_00111100 0x3C
# define BYTE_00111111 0x3F

// Base 64 decode
void decode_base64(char *msg, char *buffer, size_t bytes_to_decode);
void trim_base64_decode_input(struct s_encoding *data);
void calculate_base64_decode_output_size(struct s_encoding *data);
int validate_base64_decode_string(struct s_encoding *data);

// Base 64 encode
void calculate_base64_encode_output_size(struct s_encoding *data);
void encode_base64(uint8_t *msg, uint8_t *buffer, size_t input_size);

// Encoding functions
int encoding_command(struct s_command *command, int ind, char **argv);
int encoding_base64(void *data);



#endif
