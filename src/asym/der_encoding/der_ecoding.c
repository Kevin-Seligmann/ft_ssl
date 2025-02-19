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

struct algorithm_identifier 
{
	uint32_t octet_qty;
	uint8_t *data;
};

struct der_private_key {
	struct der_integer version;
	struct algorithm_identifier algorithm_identifier;
	struct integer_octet_string private_key;
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
	return FT_SSL_SUCCESS;
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

int encode_pkey_integer_octetstring(struct integer_octet_string *sequence, struct s_private_key *key)
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

	return FT_SSL_SUCCESS;
}

int encode_rsa_identifier_sequence(struct algorithm_identifier *sequence)
{
    uint8_t oid[] = { 0x06, 0x05, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 }; // OID bytes for RSA
    uint8_t parameters[] = { 0x05, 0x00 }; // NULL

	sequence->octet_qty = sizeof(oid) + sizeof(parameters);
	sequence->data = malloc(sequence->octet_qty);

	sequence->data[0] = oid[0];
	sequence->data[1] = oid[1];
	sequence->data[2] = oid[2];
	sequence->data[3] = oid[3];
	sequence->data[4] = oid[4];
	sequence->data[5] = oid[5];
	sequence->data[6] = oid[6];
	sequence->data[7] = oid[7];
	sequence->data[8] = oid[8];
	sequence->data[9] = oid[9];
	sequence->data[10] = oid[10];

	sequence->data[11] = parameters[0];
	sequence->data[12] = parameters[1];

	return FT_SSL_SUCCESS;
}

int encode_rsa_private_key(uint32_t *size, uint8_t **dst, struct s_private_key *key)
{
	struct der_length length; 
	struct der_private_key der_pkey;
	uint8_t *str;

	encode_integer_from_small_int(0, &der_pkey.version);
	encode_rsa_identifier_sequence(&der_pkey.algorithm_identifier);
	encode_pkey_integer_octetstring(&der_pkey.private_key, key);

	*size = 3;  // Version tag, length, octet
	*size += der_pkey.algorithm_identifier.octet_qty + 1; // Octets + tag.
	*size += der_pkey.private_key.integers_octet_length + 1; // Integers length + tag

	encode_length(*size, &length);
	*size += 1 + length.octets_qty; // Sequence tag. Sequence length.

	str = malloc(*size);
	*dst = str;

	// Main sequence
	*str = 01; // Sequence tag
	str ++;
	str += copy_length_in_buffer(str, &length);

	// Version
	str += copy_integer_in_buffer(str, &der_pkey.version);

	// Algorithm identifier
	memcpy(str, &der_pkey.algorithm_identifier.data, der_pkey.algorithm_identifier.octet_qty);
	str += der_pkey.algorithm_identifier.octet_qty;
	
	// Integers

	return FT_SSL_SUCCESS;
}
