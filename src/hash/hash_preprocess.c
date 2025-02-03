#include "ft_ssl.h"
#include "ft_hash.h"

/*
	MD5 works on little endian. SHA2 and Whirlpool need to swap the length.
	
	There is not 256 bit type. It will be assumed whirlpool messages are
	lower than 128 bits long.
*/
void append_length(struct hash_alg_data *alg, size_t message_size)
{
	if (alg->algorithm_family == ALGFAM_MD5)
	{
		uint64_t bit_length = ((uint64_t)(message_size * 8));
		ft_memcpy(alg->padded_msg + alg->padded_msg_size - 8, &bit_length, sizeof(bit_length));
	}
	else if (alg->algorithm_family == ALGFAM_SHA256)
	{
		uint64_t bit_length = __builtin_bswap64(((uint64_t) message_size) * 8);
		ft_memcpy(alg->padded_msg + alg->padded_msg_size - 8, &bit_length, sizeof(bit_length));
	}
	else if (alg->algorithm_family == ALGFAM_SHA512)
	{
		__uint128_t bit_length = __builtin_bswap128(((__uint128_t) message_size) * 8);
		ft_memcpy(alg->padded_msg + alg->padded_msg_size - 16, &bit_length, sizeof(bit_length));
	}
	else if (alg->algorithm_family == ALGFAM_WHIRLPOOL)
	{
		__uint128_t low = 0;
		__uint128_t bit_length = __builtin_bswap128(((__uint128_t) message_size) * 8);
		ft_memcpy(alg->padded_msg + alg->padded_msg_size - 16, &bit_length, sizeof(bit_length));
		ft_memcpy(alg->padded_msg + alg->padded_msg_size - 32, &low, sizeof(low));
	}
}

void fill_padded_message(struct hash_alg_data *alg, size_t message_size, size_t remaining_bytes)
{
	// Copy message
	ft_memcpy(alg->padded_msg, alg->msg, message_size);

	// Append 10000000 byte
	alg->padded_msg[message_size] = 0x80;

	// Set 0s from the last byte to before the length buffer
	ft_memset(alg->padded_msg + message_size + 1, 0, remaining_bytes);

	append_length(alg, message_size);
}

void pad_message(struct hash_alg_data *alg)
{
	size_t message_size;
	size_t remaining_bytes;

	message_size = ft_strlen((char *) (alg->msg));

 	// A 0x80 (10000000) byte is always added.
	alg->padded_msg_size = message_size + 1;

	// A length of certain size is always added.
	alg->padded_msg_size += alg->length_padding_size;

 	// How many bytes are left such that the padded message is a factor of the block size. 
	// (Block size - Remained of block size) % block size (Edge case)
	remaining_bytes = (alg->msg_block_size - (alg->padded_msg_size % alg->msg_block_size)) % alg->msg_block_size;

	alg->padded_msg_size += remaining_bytes;
	alg->padded_msg = malloc(alg->padded_msg_size);
	if (!alg->padded_msg)
	{
		write_error2("Memory error", strerror(errno));
		return ;
	}
	fill_padded_message(alg, message_size, remaining_bytes);
}

void alloc_hash_values(struct hash_alg_data *alg)
{
	alg->h = malloc(alg->hash_values_qty * BITS_TO_BYTES(alg->hash_values_bit_size));
	if (!alg->h)
	{
		write_error2("Memory error", strerror(errno));
		return ;
	}
}

int preprocess_sha2(struct hash_alg_data *alg)
{
	alloc_hash_values(alg);
	pad_message(alg);
	if (alg->h == NULL || alg->padded_msg == NULL)
	{
		free(alg->h);
		free(alg->padded_msg);
		return FT_SSL_FATAL_ERR;
	}
	return FT_SSL_SUCCESS;
}

int preprocess_md5(struct hash_alg_data *alg)
{
	return preprocess_sha2(alg);
}

int preprocess_whirlpool(struct hash_alg_data *alg)
{
	return preprocess_sha2(alg);
}
