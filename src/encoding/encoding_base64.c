#include "ft_ssl.h"
#include "ft_encoding.h"

static int allocate_buffer(struct s_encoding *data)
{
	if (data->flags & FLAG_DECODE)
	{
		trim_base64_decode_input(data);
		if (validate_base64_decode_string(data) != FT_SSL_SUCCESS)
		{
			data->input = NULL;
			return FT_SSL_TRIVIAL_ERR;
		}
		calculate_base64_decode_output_size(data);
	}
	else
		calculate_base64_encode_output_size(data);
	data->output = malloc(data->output_size + 1);
	if (data->output == NULL)
		write_error2("Memory error", strerror(errno));
	return FT_SSL_SUCCESS;
}

int encoding_base64(void *data)
{
	struct s_encoding *encoding_data;
	int ret;

	encoding_data = (struct s_encoding *) data;
	ret = allocate_buffer(encoding_data);
	if (ret != FT_SSL_SUCCESS)
		return ret;
	if (encoding_data->flags & FLAG_DECODE)
		decode_base64(encoding_data->input, encoding_data->output, encoding_data->input_size);
	else
		encode_base64((uint8_t *) encoding_data->input, (uint8_t *) encoding_data->output, encoding_data->input_size);
	return  FT_SSL_SUCCESS;
}
