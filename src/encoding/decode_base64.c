#include "ft_ssl.h"
#include "ft_encoding.h"

static char get_decode_byte(char *msg, size_t bytes_decoded, size_t input_size)
{
	char *ptr;
	size_t base_ind;

	if (bytes_decoded >= input_size)
		return -1;
	base_ind = 0;
	while (BASE64[base_ind])
	{
		if (BASE64[base_ind] == msg[bytes_decoded])
			return base_ind;
		base_ind ++;
	}
	return -1;
}

static void put_decode_byte(char *buffer, char a, char b, char c, char d)
{
	(*buffer) = (a << 2) | (b >> 4);
	buffer++;
	if (c != -1)
		(*buffer) = (b << 4) | (c >> 2);
	buffer++;
	if (c != -1 && d != -1)
		(*buffer) = (c << 6) | d;
}

void decode_base64(char *msg, char *buffer, size_t input_size)
{
	char a;
	char b;
	char c;
	char d;
	size_t bytes_decoded;
	
	bytes_decoded = 0;
	while (bytes_decoded < input_size)
	{
		a = get_decode_byte(msg, bytes_decoded++, input_size);
		b = get_decode_byte(msg, bytes_decoded++, input_size);
		c = get_decode_byte(msg, bytes_decoded++, input_size);
		d = get_decode_byte(msg, bytes_decoded++, input_size);
		put_decode_byte(buffer, a, b, c, d);
		(buffer) += 3;
	}
}

void trim_base64_decode_input(struct s_encoding *data)
{
	size_t erased_qty;
	size_t ind;

	erased_qty = 0;
	ind = 0;
	while (ind < data->input_size)
	{
		if (ft_strchr(BASE64_WHITESPACE, data->input[ind]) != 0)
			erased_qty ++;
		else if (erased_qty)
			data->input[ind - erased_qty] = data->input[ind];
		ind ++;
	}
	data->input[ind - erased_qty] = data->input[ind - 1];
	data->input_size -= erased_qty;
}

void calculate_base64_decode_output_size(struct s_encoding *data)
{
	data->output_size = data->input_size;
	if (data->output_size % 4 != 0)
	{
		data->output_size -= data->output_size % 64;
		data->output_size = (data->output_size / 4) * 3;
	}
	else 
	{
		data->output_size = (data->output_size / 4) * 3;
		if (data->input[data->input_size - 1] == BASE64_PAD_BYTE)
			data->output_size --;
		if (data->input[data->input_size - 2] == BASE64_PAD_BYTE)
			data->output_size --;
	}
}

int validate_base64_decode_string(struct s_encoding *data)
{
	size_t ind;
 
	ind = 0;
	if (data->input_size < 4 || (data->input_size <= 64 && data->input[data->input_size] != '\n'))
		return FT_SSL_FATAL_ERR;
	while (ind < data->input_size)
	{
		if (ft_strchr(BASE64, data->input[ind]) == 0)
		{
			if (data->input[ind] != BASE64_PAD_BYTE)
				return FT_SSL_FATAL_ERR;
			if (ind + 1 == data->input_size)
				return FT_SSL_SUCCESS;
			if (data->input[ind + 1] != BASE64_PAD_BYTE)
				return FT_SSL_FATAL_ERR;
			if (ind + 2 == data->input_size)
				return FT_SSL_SUCCESS;
			return FT_SSL_FATAL_ERR;
		}
		ind ++;
	}
	return FT_SSL_SUCCESS;
}
