#include "ft_ssl.h"
#include "ft_encoding.h"

static void set_encode_byte(uint8_t *buffer, size_t *written_bytes, uint32_t a, uint32_t b, uint32_t c)
{
	buffer[(*written_bytes) ++] = BASE64[a >> 2];
	if (b != 256)
		buffer[(*written_bytes) ++] = BASE64[((a << 4) & BYTE_00110000) | (b >> 4)];
	else
		buffer[(*written_bytes) ++] = BASE64[((a << 4) & BYTE_00110000)];
	if (b != 256 && c != 256)
		buffer[(*written_bytes) ++] = BASE64[((b << 2) & BYTE_00111100) | (c >> 6)];
	else if (b != 256)
		buffer[(*written_bytes) ++] = BASE64[((b << 2) & BYTE_00111100)];
	else
		buffer[(*written_bytes) ++] = BASE64_PAD_BYTE;
	if (c != 256)
		buffer[(*written_bytes) ++] = BASE64[c & BYTE_00111111];
	else
		buffer[(*written_bytes) ++] = BASE64_PAD_BYTE;
}

void encode_base64(uint8_t *msg, uint8_t *buffer, size_t input_size)
{
	uint32_t a, b, c;
	size_t read_bytes;
	size_t written_bytes;

	read_bytes = 0;
	written_bytes = 0;
	while (read_bytes < input_size)
	{
		a = msg[read_bytes];
		b = 256;
		c = 256;
		if (read_bytes + 1 < input_size)
			b = (uint32_t) msg[read_bytes + 1];
		if (read_bytes + 2 < input_size)
			c = (uint32_t) msg[read_bytes + 2];
		read_bytes += 3;
		set_encode_byte(buffer, &written_bytes, a, b, c);
	}
	buffer[written_bytes] = 0;
}

void calculate_base64_encode_output_size(struct s_encoding *data)
{
	size_t aux;

	data->output_size = (data->input_size / 3);
	aux = data->input_size % 3;
	if (aux)
		data->output_size ++;
	data->output_size *= 4;
}
