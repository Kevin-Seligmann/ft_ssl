#include "ft_ssl.h"
#include "ft_encryption.h"
#include "ft_bitwise.h"

// https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf

static int get_mode(int flags)
{
	if (flags & FLAG_DECODE)
		return FLAG_DECODE;
	return FLAG_ENCODE;
}

// ECB
static void perform_des_ecb(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;

	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		process_block(input, output, keys, get_mode(data->flags));
	}

}

// CBC
static void perform_des_cbc(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;

	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		if (!(data->flags & FLAG_DECODE))
		{
			process_block(input ^ vector, output, keys, get_mode(data->flags));
			vector = *output;
		}
		else
		{
			process_block(input, output, keys, get_mode(data->flags));
			*output ^= vector;
			vector = input;
		}
	}
}

// PCBC
static void perform_des_pcbc(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;

	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		if (!(data->flags & FLAG_DECODE))
		{
			process_block(input ^ vector, output, keys, get_mode(data->flags));
			vector = (*output) ^ input;
		}
		else
		{
			process_block(input, output, keys, get_mode(data->flags));
			*output ^= vector;
			vector = (*output) ^ input;
		}
	}
}

// CFB
static void perform_des_cfb(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;

	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		if (!(data->flags & FLAG_DECODE))
		{
			process_block(vector, output, keys, get_mode(data->flags));
			(*output) ^= input;
			vector = (*output); 
		}
		else
		{
			process_block(vector, output, keys, get_mode(data->flags));
			*output ^= input;
			vector = input;
		}
	}
}

// OFB
static void perform_des_ofb(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;

	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		process_block(vector, output, keys, get_mode(data->flags));
		vector = (*output); 
		(*output) ^= input;
	}
}

// CTR
static uint64_t calculate_ctr_vector(uint64_t vector, uint32_t counter)
{
	return ((vector & 0xFFFFFFFF00000000) | counter);
}

static void perform_des_ctr(struct s_encryption *data, uint64_t keys[DES_ROUND_COUNT], uint64_t vector)
{
	uint64_t input;
	uint64_t *output;
	uint32_t counter;

	counter = 0;
	for (size_t processed_bytes = 0; processed_bytes < data->input_length; processed_bytes += CIPHER_BLOCK_SIZE)
	{
		input = (*((uint64_t *) (data->source_buffer + processed_bytes)));
		output = (uint64_t *) (data->result_buffer + processed_bytes);
		vector = calculate_ctr_vector(vector, counter);
		process_block(vector, output, keys, get_mode(data->flags));
		(*output) ^= input;
		counter ++;
	}
}

// Pre-processing
static int allocate_result_buffer(struct s_encryption *data)
{
	size_t pad_bytes;

	pad_bytes = (CIPHER_BLOCK_SIZE - data->input_length % CIPHER_BLOCK_SIZE) % CIPHER_BLOCK_SIZE;
	data->output_length = data->input_length;
	data->result_buffer = malloc(data->output_length + pad_bytes);
	if (data->result_buffer == NULL)
	{
		write_error2("Memory error", strerror(errno));
		return (FT_SSL_FATAL_ERR);
	}
	ft_memset(data->result_buffer + data->output_length, 0, pad_bytes);
	return FT_SSL_SUCCESS;
}

static uint64_t get_vector_from_buffer(struct s_encryption *data)
{
	return *((uint64_t *) (data->ksiv_buffer + data->key_length + data->salt_length));
}

// Command entry point
static int des_encryption(struct s_encryption *data, void (*block_cipher_mode)(struct s_encryption *, uint64_t [DES_ROUND_COUNT], uint64_t))
{
	if (allocate_result_buffer(data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	generate_key_schedule((uint64_t *) data->ksiv_buffer, data->keys);
	block_cipher_mode(data, data->keys, get_vector_from_buffer(data));
	return FT_SSL_SUCCESS;
}

int des_ecb_command(void *data)
{
	return des_encryption(data, perform_des_ecb);
}

int des_cbc_command(void *data)
{
	return des_encryption(data, perform_des_cbc);
}

int des_pcbc_command(void *data)
{
	return des_encryption(data, perform_des_pcbc);
}

int des_cfb_command(void *data)
{
	return des_encryption(data, perform_des_cfb);
}

int des_ofb_command(void *data)
{
	return des_encryption(data, perform_des_ofb);
}

int des_ctr_command(void *data)
{
	return des_encryption(data, perform_des_ctr);
}

//
// Des-ede
static void swap_output_and_input(struct s_encryption *data)
{
	char *aux_p;
	size_t aux;

	aux_p = data->source_buffer;
	data->source_buffer = data->result_buffer;
	data->result_buffer = aux_p;

	aux = data->input_length;
	data->input_length = data->output_length;
	data->output_length = aux;

	ft_memset(data->result_buffer, 0, data->output_length);
}

static int des_ede_encryption(struct s_encryption *data, void (*block_cipher_mode)(struct s_encryption *, uint64_t [DES_ROUND_COUNT], uint64_t))
{
	uint64_t keys_1[DES_ROUND_COUNT];
	uint64_t keys_2[DES_ROUND_COUNT];
	uint64_t vector;

	if (allocate_result_buffer(data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	generate_key_schedule((uint64_t *) data->ksiv_buffer, keys_1);
	generate_key_schedule((uint64_t *) (data->ksiv_buffer + SINGLE_DES_KEYLEN), keys_2);
	vector = get_vector_from_buffer(data);
	block_cipher_mode(data, keys_1, vector);
	swap_output_and_input(data);
	block_cipher_mode(data, keys_2, vector);
	swap_output_and_input(data);
	block_cipher_mode(data, keys_1, vector);
	return FT_SSL_SUCCESS;
}

int des_ede_ecb_command(void *data)
{
	return des_ede_encryption(data, perform_des_ecb);
}

int des_ede_cbc_command(void *data)
{
	return des_ede_encryption(data, perform_des_cbc);
}

int des_ede_pcbc_command(void *data)
{
	return des_ede_encryption(data, perform_des_pcbc);
}

int des_ede_cfb_command(void *data)
{
	return des_ede_encryption(data, perform_des_cfb);
}

int des_ede_ofb_command(void *data)
{
	return des_ede_encryption(data, perform_des_ofb);
}

int des_ede_ctr_command(void *data)
{
	return des_ede_encryption(data, perform_des_ctr);
}

// des-ede3
static int des_ede3_encryption(struct s_encryption *data, void (*block_cipher_mode)(struct s_encryption *, uint64_t [DES_ROUND_COUNT], uint64_t))
{
	uint64_t keys_1[DES_ROUND_COUNT];
	uint64_t keys_2[DES_ROUND_COUNT];
	uint64_t keys_3[DES_ROUND_COUNT];
	uint64_t vector;

	if (allocate_result_buffer(data) == FT_SSL_FATAL_ERR)
		return FT_SSL_FATAL_ERR;
	generate_key_schedule((uint64_t *) data->ksiv_buffer, keys_1);
	generate_key_schedule((uint64_t *) (data->ksiv_buffer + SINGLE_DES_KEYLEN), keys_2);
	generate_key_schedule((uint64_t *) (data->ksiv_buffer + 2 * SINGLE_DES_KEYLEN), keys_3);
	vector = get_vector_from_buffer(data);
	block_cipher_mode(data, keys_1, vector);
	swap_output_and_input(data);
	block_cipher_mode(data, keys_2, vector);
	swap_output_and_input(data);
	block_cipher_mode(data, keys_3, vector);
	return FT_SSL_SUCCESS;
}

int des_ede3_ecb_command(void *data)
{
	return des_ede3_encryption(data, perform_des_ecb);
}

int des_ede3_cbc_command(void *data)
{
	return des_ede3_encryption(data, perform_des_cbc);
}

int des_ede3_pcbc_command(void *data)
{
	return des_ede3_encryption(data, perform_des_pcbc);
}

int des_ede3_cfb_command(void *data)
{
	return des_ede3_encryption(data, perform_des_cfb);
}

int des_ede3_ofb_command(void *data)
{
	return des_ede3_encryption(data, perform_des_ofb);
}

int des_ede3_ctr_command(void *data)
{
	return des_ede3_encryption(data, perform_des_ctr);
}
