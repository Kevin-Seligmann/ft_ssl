#include "ft_ssl.h"
#include "ft_asym.h"
#include "ft_encoding.h"

int output_private_key(struct s_genrsa_command *genrsa)
{
	return 0;
	// struct der_encoding der_encoding_data;
	// struct s_encoding base64_encoding_data;

	// der_encoding_data.operation = ENCODE_RSA;
	// der_encoding_data.data = &genrsa->pkey;
	// if (der_encoding(&der_encoding) == FT_SSL_FATAL_ERR)
	// 	return FT_SSL_FATAL_ERR;

	// base64_encoding_data.input = (char *) der_encoding_data.enc_result;
	// base64_encoding_data.input_size = der_encoding_data.enc_result_length;
	// encoding_base64(&base64_encoding_data);
	// if (base64_encoding_data.output == NULL)
	// {
	// 	free(der_encoding_data.enc_result);
	// 	write_error("error encoding private key on base64");
	// 	return FT_SSL_FATAL_ERR;
	// }

	// ft_putstr_fd("-----BEGIN PRIVATE KEY-----\n", genrsa->fd_out);
	// ft_putstr_fd(base64_encoding_data.output, genrsa->fd_out);
	// ft_putstr_fd("\n-----END PRIVATE KEY-----\n", genrsa->fd_out);

	// free(base64_encoding_data.output);
	// free(der_encoding_data.enc_result);
	// return FT_SSL_SUCCESS;	
}
