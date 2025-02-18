#include "ft_ssl.h"
#include "ft_asym.h"


struct der_length {
	uint32_t octets_qty;
	uint8_t *octets;
};

struct der_integer {
	struct der_length length;
	uint32_t octets_qty;
	uint8_t *octets;
};

struct integer_octet_string 
{
	struct der_length length;
	uint32_t integer_qty;
	uint32_t integers_octet_length;
	struct der_integer *integers;	
};


int encode_length_short_form(uint32_t octet_qty, struct der_length *length)
{
	uint8_t octet;

	octet = (uint8_t) octet_qty;
	length->octets_qty = 1;
	length->octets = malloc(1);
	length->octets[0] = octet;
	return FT_SSL_SUCCESS;
}

int encode_length_long_form(uint32_t octet_qty, struct der_length *length)
{
	uint32_t bit_count;
	uint8_t *octet_qty_buffer;

	bit_count = 32 - __builtin_clz(octet_qty);
	length->octets_qty = ((bit_count + 7) / 8) + 1; // Plus octet that tells the quantity of octets that determine the length.
	length->octets = malloc(length->octets_qty);

	octet_qty = __builtin_bswap32(octet_qty); // Transforms to big endian.
	octet_qty_buffer = (uint8_t *) &octet_qty;
	length->octets[0] = length->octets_qty - 1;
	if (length->octets_qty == 1)
		length->octets[1] = octet_qty_buffer[0];
	if (length->octets_qty == 2)
		length->octets[2] = octet_qty_buffer[1];
	if (length->octets_qty == 3)
		length->octets[3] = octet_qty_buffer[2];
	if (length->octets_qty == 4)
		length->octets[4] = octet_qty_buffer[3];
}

int encode_length(uint32_t octet_qty, struct der_length *length)
{
	if (octet_qty <= 127)
		return encode_length_short_form(octet_qty, length);
	return encode_length_long_form(octet_qty, length);
}

int encode_integer_from_bigint(BIGNUM *src, struct der_integer *integer)
{
	int leading_one;

	leading_one = BN_is_bit_set(src, BN_num_bits(src) - 1);
	if (leading_one)
	{
		integer->octets_qty = BN_num_bytes(src) + 1;
		integer->octets = malloc(integer->octets_qty);
		BN_bn2bin(src, integer->octets + 1);
		integer->octets[0] = 0;
	}
	else 
	{
		integer->octets_qty = BN_num_bytes(src);
		integer->octets = malloc(integer->octets_qty);
		BN_bn2bin(src, integer->octets );
	}
	encode_length(integer->octets_qty, &integer->length);
	return FT_SSL_SUCCESS;
}

// 1 to 127
int encode_integer_from_small_int(uint8_t src, struct der_integer *integer)
{
	integer->octets_qty = 1;
	integer->octets = malloc(1);
	integer->octets[0] = src;
	encode_length(integer->octets_qty, &integer->length);
	return FT_SSL_SUCCESS;
}

struct s_private_key {
	int version;
	BIGNUM *modulus;
	BIGNUM *public_exponent;
	BIGNUM *private_exponent;
	BIGNUM *prime_1;
	BIGNUM *prime_2;
	BIGNUM *exponent_1;
	BIGNUM *exponent_2;
	BIGNUM *coefficient;
};


int encode_pkey_integer_sequence(struct integer_octet_string *sequence, struct s_private_key *key)
{
	sequence->integer_qty = 9; // Private keys hold 9 integers.
	sequence->integers = malloc(9 * sizeof(* (sequence->integers)));
	encode_integer_from_small_int(key->version, sequence->integers);
	encode_integer_from_bigint(key->modulus, sequence->integers + 1);
	encode_integer_from_bigint(key->public_exponent, sequence->integers + 2);
	encode_integer_from_bigint(key->private_exponent, sequence->integers + 3);
	encode_integer_from_bigint(key->prime_1, sequence->integers + 4);
	encode_integer_from_bigint(key->prime_2, sequence->integers + 5);
	encode_integer_from_bigint(key->exponent_1, sequence->integers + 6);
	encode_integer_from_bigint(key->exponent_2, sequence->integers + 7);
	encode_integer_from_bigint(key->coefficient, sequence->integers + 8);

	sequence->integers_octet_length = 0;
	for (int i = 0; i < 9; i ++)
	{
		// Identifier + Integer's octets + Length octets.
		sequence->integers_octet_length += 1 + sequence->integers[i].octets_qty + sequence->integers[i].length.octets_qty; 
	}

	encode_length(sequence->integers_octet_length, &sequence->length);
}
