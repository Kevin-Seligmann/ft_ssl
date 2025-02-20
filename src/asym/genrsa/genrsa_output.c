#include "ft_ssl.h"
#include "ft_asym.h"
#include "ft_encoding.h"

static void prepare_base64_enc_request(struct s_encoding *base64enc, uint64_t length, uint8_t *str)
{
	base64enc->flags = FLAG_ENCODE;
	base64enc->input = (char *) str;
	base64enc->input_size = length;
}

static int exit_output(int ret, uint8_t *der_encoded_key, uint8_t *pem_encoded_key)
{
	free(der_encoded_key);
	free(pem_encoded_key);
	return ret;
}

static void write_output(struct s_encoding *base64enc, int fdout, int cpks1)
{
	if (cpks1)
		write(fdout, PKCS1_PRIV_KEY_BEGIN, ft_strlen(PKCS1_PRIV_KEY_BEGIN));
	else
		write(fdout, PKCS8_PRIV_KEY_BEGIN, ft_strlen(PKCS8_PRIV_KEY_BEGIN));
	for (size_t printed_bytes = 0; printed_bytes < base64enc->output_size; printed_bytes += 64)
	{
		if (base64enc->output_size > 64 + printed_bytes)
			write (fdout, base64enc->output + printed_bytes, 64);
		else
			write (fdout, base64enc->output + printed_bytes,base64enc->output_size - printed_bytes);
		ft_putchar_fd('\n', fdout);
	}
	if (cpks1)
		write(fdout, PKCS1_PRIV_KEY_END, ft_strlen(PKCS1_PRIV_KEY_END));
	else
		write(fdout, PKCS8_PRIV_KEY_END, ft_strlen(PKCS8_PRIV_KEY_END));
}

int output_private_key(struct s_genrsa_command *genrsa, int cpks1)
{
	struct s_encoding base64enc;
	uint8_t *der_encoded_key;
	uint32_t der_encoded_key_length;

	if (encode_rsa_private_key(&der_encoded_key_length, &der_encoded_key, &genrsa->pkey, cpks1) == FT_SSL_FATAL_ERR)
		return exit_output(FT_SSL_FATAL_ERR, der_encoded_key, NULL);
	prepare_base64_enc_request(&base64enc, der_encoded_key_length, der_encoded_key);
	if (encoding_base64(&base64enc) == FT_SSL_FATAL_ERR)
		exit_output(FT_SSL_FATAL_ERR, der_encoded_key, NULL);
	write_output(&base64enc, genrsa->fd_out, cpks1);
	return exit_output(FT_SSL_SUCCESS, der_encoded_key, (uint8_t *) base64enc.output);
}
