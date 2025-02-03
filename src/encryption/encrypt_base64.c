#include "ft_ssl.h"
#include "ft_encryption.h"
#include "ft_encoding.h"

int decode_ciphertext_base64(struct s_command *command, struct s_encryption *data)
{
	struct s_encoding encoding_data;

	encoding_data.flags = FLAG_DECODE;
	encoding_data.input = data->source_buffer;
	encoding_data.input_size = data->input_length;
	if (encoding_base64(&encoding_data) != FT_SSL_SUCCESS)
		return FT_SSL_FATAL_ERR;
	free(data->source_buffer);
	data->source_buffer = encoding_data.output;
	data->input_length = encoding_data.output_size;
	return FT_SSL_SUCCESS;
}

int encode_ciphertext_base64(struct s_command *command, struct s_encryption *data)
{
	struct s_encoding encoding_data;

	encoding_data.flags = FLAG_ENCODE;
	encoding_data.input = data->result_buffer;
	encoding_data.input_size = data->output_length;
	if (encoding_base64(&encoding_data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	free(data->result_buffer);
	data->result_buffer = encoding_data.output;
	data->output_length = encoding_data.output_size;
	return FT_SSL_SUCCESS;
}
