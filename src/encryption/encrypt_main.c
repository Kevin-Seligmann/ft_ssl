#include "ft_ssl.h"
#include "ft_encryption.h"
#include "ft_hash.h"

// https://datatracker.ietf.org/doc/html/rfc8018#section-5.1

static void set_data(struct s_command *command, struct s_encryption *data)
{
	ft_memset(data, 0, sizeof(*data));
	data->flags = command->flags;
	data->encryption_mode = get_encryption_mode(command->meta_info.algorithm);
	data->cipher_mode = get_cipher_mode(command->meta_info.algorithm);
}

static int allocate_ksiv_data(struct s_command *command, struct s_encryption *data)
{
	data->key_length = get_key_length(data->encryption_mode);
	data->salt_length = DES_SALT_LENGTH;
	data->iv_length = DES_IV_LENGTH;
	data->ksiv_buffer = malloc(data->salt_length + data->iv_length + data->key_length);
	if (data->ksiv_buffer == NULL)
	{
		write_error2("Memory error", strerror(errno));
		return FT_SSL_FATAL_ERR;
	}
	return FT_SSL_SUCCESS;
}

static int free_encryption_command_w_ret(struct s_encryption *data, int ret)
{
	free(data->ksiv_buffer);
	free(data->source_buffer);
	free(data->result_buffer);
	free(data->encoded_result_buffer);
	free(data->decoded_source_buffer);
	return ret;
}

static int validate_decode_input(struct s_encryption *data)
{
	if(data->cipher_mode == CFB_MODE || data->cipher_mode == OFB_MODE)
		return FT_SSL_SUCCESS;
	if (data->input_length % CIPHER_BLOCK_SIZE != 0 || data->input_length < CIPHER_BLOCK_SIZE)
	{
		write_error("Invalid decoding input length");
		return FT_SSL_FATAL_ERR;
	}
	return FT_SSL_SUCCESS;
}

int encryption_command(struct s_command *command, int ind, char **argv)
{
	struct s_encryption data;
	int ret;

	ret = FT_SSL_SUCCESS;
	if (command->flags & FLAG_ENCODE && command->flags & FLAG_DECODE)
	{
		write_error2(command->meta_info.command_name, "Incompatible encode and decode flags.");
		return FT_SSL_FATAL_ERR;
	}
	if (argv[ind])
	{
		write_error2(command->meta_info.command_name, "Invalid argument syntax.");
		return FT_SSL_FATAL_ERR;
	}
	set_data(command, &data);  // KSIV malloc'd.
	if (allocate_ksiv_data(command, &data) == FT_SSL_FATAL_ERR) 
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (command->flags & FLAG_FLAG_KEY && get_salt(command, &data) == FT_SSL_FATAL_ERR)
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (get_salt(command, &data) == FT_SSL_FATAL_ERR)
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (get_keys(command, &data) == FT_SSL_FATAL_ERR)
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (get_initialization_vector(command, &data) == FT_SSL_FATAL_ERR)
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (command->flags & FLAG_DEBUG)
	{
		ret = print_debug_info(command, &data);
		return free_encryption_command_w_ret(&data, ret);
	}
	if (get_text_to_transform(command, &data) == FT_SSL_FATAL_ERR) // Source malloc'd.
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (command->flags & FLAG_BASE64_ENCRYPTION && command->flags & FLAG_DECODE)
		if (decode_ciphertext_base64(command, &data) == FT_SSL_FATAL_ERR) // Decoded source malloc'd
			return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (command->flags & FLAG_DECODE && validate_decode_input(&data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	if (command->meta_info.algorithm_function(&data) == FT_SSL_FATAL_ERR) // Result malloc'd
		return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	if (command->flags & FLAG_BASE64_ENCRYPTION && !(command->flags & FLAG_DECODE))
		if (encode_ciphertext_base64(command, &data) == FT_SSL_FATAL_ERR) // Encoded result malloc'd
			return free_encryption_command_w_ret(&data, FT_SSL_FATAL_ERR);
	ret = output_encryption_result(command, &data);
	return free_encryption_command_w_ret(&data, ret);
}
