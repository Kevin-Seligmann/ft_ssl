#include "ft_ssl.h"
#include "ft_asym.h"

/* RSA ENCRYPTION

	PKCS #8. Encoding. https://datatracker.ietf.org/doc/html/rfc5208
	PrivateKeyInfo ::= SEQUENCE {
		version                   Version,
		privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
		privateKey                PrivateKey,
	}
	Version ::= INTEGER (0)
	PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
	PrivateKey ::= OCTET STRING (RSAPrivateKey)


	PKCS #1. https://datatracker.ietf.org/doc/html/rfc3447#section-3.1. RSA Private key.
	RSAPrivateKey ::= SEQUENCE {
		version           Version,
		modulus           INTEGER,  -- n
		publicExponent    INTEGER,  -- e
		privateExponent   INTEGER,  -- d
		prime1            INTEGER,  -- p
		prime2            INTEGER,  -- q
		exponent1         INTEGER,  -- d mod (p-1)
		exponent2         INTEGER,  -- d mod (q-1)
		coefficient       INTEGER,  -- (inverse of q) mod p
	}
	Version ::= INTEGER (0)


	x.509 Private Key Algorithm Identifier. https://datatracker.ietf.org/doc/html/rfc5280
	AlgorithmIdentifier  ::=  SEQUENCE  {
		algorithm               OBJECT IDENTIFIER,
		parameters              ANY DEFINED BY algorithm OPTIONAL
	}
	parameters = NULL (0x05 0x00)

	https://datatracker.ietf.org/doc/html/rfc4055:
    rsaEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 1 }

	https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.1:
	pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
                     rsadsi(113549) pkcs(1) 1 }

*/

/*
	Length management
*/


static int get_length_length(uint32_t length)
{
	uint32_t length_length;
	uint32_t bit_count;

	if (length <= 127)
		return 1;
	bit_count = 32 - __builtin_clz(length);
	length_length = ((bit_count + 7) / 8) + 1; // Plus first byte.
	return length_length;
}

static int get_integer_der_length_from_bigint(BIGNUM *num)
{
	uint32_t length;
 	int leading_one;

	// If the num has a leading one, an extra byte must be allocated
	leading_one = (BN_num_bits(num) % 8 == 0);
	if (leading_one)
		length = BN_num_bytes(num) + 1;
	else 
		length = BN_num_bytes(num);
	length += get_length_length(length) + 1; // Add the length octets and integer tag
	return length;
}

// The OID itself is 9 octets, add length and oid
static int get_rsa_oid_length()
{
	return 11; 
}

// TAG + Length + NULL (2) + OID
static int get_rsa_identifier_length()
{
	return 2 + get_rsa_oid_length() + 2;
}

static int get_pkey_sequence_data_length(struct s_private_key *key)
{
	uint32_t length;

	length = 3; // Version is 3 octets
	length += get_integer_der_length_from_bigint(key->public_exponent);
	length += get_integer_der_length_from_bigint(key->private_exponent);
	length += get_integer_der_length_from_bigint(key->prime_2);
	length += get_integer_der_length_from_bigint(key->prime_1);
	length += get_integer_der_length_from_bigint(key->modulus);
	length += get_integer_der_length_from_bigint(key->exponent_2);
	length += get_integer_der_length_from_bigint(key->exponent_1);
	length += get_integer_der_length_from_bigint(key->coefficient);
	return length;
}

static int get_pkey_sequence_length(struct s_private_key *key)
{
	uint32_t length;

	length = get_pkey_sequence_data_length(key);
	length += get_length_length(length) + 1; // Add the length octets and sequence tag
	return length;
}


static int get_pkey_octetstring_data_length(struct s_private_key *key)
{
	return get_pkey_sequence_length(key);;
}

static int get_pkey_octetstring_length(struct s_private_key *key)
{
	uint32_t length;

	length = get_pkey_octetstring_data_length(key);
	length += get_length_length(length) + 1; // Add the length octets and octetstring tag
	return length;
}

static void encode_length(uint32_t *copied_octets, uint8_t *dst, uint32_t length)
{
	uint32_t length_length;
	uint32_t bit_count;

	if (length < 127)
	{
		*dst = (uint8_t) length;
		(*copied_octets) ++;
		return ;
	}
	bit_count = 32 - __builtin_clz(length);
	length_length = ((bit_count + 7) / 8);
	dst[0] = 0x80 | length_length;

	length = __builtin_bswap32(length);
	memcpy(dst + 1, (uint8_t *) &length + (4 - length_length), length_length);
	(*copied_octets) += length_length + 1;
}



/*
	Encoding values
*/

static void encode_small_tag(uint32_t *copied_octets, uint8_t *dst, uint8_t tag)
{
	*dst = tag;
	(*copied_octets) ++;
}

static void encode_small_integer(uint32_t *copied_octets, uint8_t *dst, uint8_t integer)
{
	encode_small_tag(copied_octets, dst, DER_INTEGER);
	encode_length(copied_octets, dst + 1, 1);
	*(dst + 2) = integer;
	(*copied_octets) ++;
}

static void encode_null(uint32_t *copied_octets, uint8_t *dst)
{
	encode_small_tag(copied_octets, dst, DER_NULL);
	encode_length(copied_octets, dst + 1, 0);
}

static void encode_bigint(uint32_t *copied_octets, uint8_t *dst, BIGNUM *num)
{
	int leading_one;
	uint32_t bigint_copied_octets;
    uint32_t length;

	leading_one = (BN_num_bits(num) % 8 == 0);
	length = BN_num_bytes(num);
	if (leading_one)
		length ++;

	bigint_copied_octets = 0;
	encode_small_tag(&bigint_copied_octets, dst, DER_INTEGER);
	encode_length(&bigint_copied_octets, dst + bigint_copied_octets, length);

	if (leading_one) // If leading one, add 0x00
	{
		(dst + bigint_copied_octets)[0] = 0;
		BN_bn2bin(num, dst + bigint_copied_octets + 1);
	}
	else
		BN_bn2bin(num, dst + bigint_copied_octets);
	bigint_copied_octets += length;
	(*copied_octets) += bigint_copied_octets;
}

static void encode_pkey_sequence(uint32_t *copied_octets, uint8_t *dst, struct s_private_key *key)
{
	uint32_t octetstring_copied_octets;

	octetstring_copied_octets = 0;
	encode_small_tag(&octetstring_copied_octets, dst + octetstring_copied_octets, DER_SEQUENCE);
	encode_length(&octetstring_copied_octets, dst + octetstring_copied_octets,  get_pkey_sequence_data_length(key));
	encode_small_integer(&octetstring_copied_octets, dst + octetstring_copied_octets, key->version);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->modulus);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->public_exponent);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->private_exponent);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->prime_1);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->prime_2);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->exponent_1);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->exponent_2);
	encode_bigint(&octetstring_copied_octets, dst + octetstring_copied_octets, key->coefficient);
	(*copied_octets) += octetstring_copied_octets;
}

static void encode_pkey_octetstring(uint32_t *copied_octets, uint8_t *dst, struct s_private_key *key)
{
	uint32_t octetstring_copied_octets;

	octetstring_copied_octets = 0;
	encode_small_tag(&octetstring_copied_octets, dst, DER_OCTETSTRING);
	encode_length(&octetstring_copied_octets, dst + octetstring_copied_octets,  get_pkey_octetstring_data_length(key));
	encode_pkey_sequence(&octetstring_copied_octets, dst + octetstring_copied_octets, key);
	(*copied_octets) += octetstring_copied_octets;
}

static void encode_rsa_identifier(uint32_t *copied_octets, uint8_t *dst)
{
	uint32_t copied_identifier_octets;
	uint8_t identifier[9] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

	copied_identifier_octets = 0;
    encode_small_tag(&copied_identifier_octets, dst, DER_SEQUENCE);
    encode_length(&copied_identifier_octets, dst + copied_identifier_octets, 13); // NULL (2), OID Data (9), OID tag (1), OID length (1)

    encode_small_tag(&copied_identifier_octets, dst + copied_identifier_octets, DER_OID);
    encode_length(&copied_identifier_octets, dst + copied_identifier_octets, 9);
    memcpy(dst + copied_identifier_octets, identifier, 9);
    copied_identifier_octets += 9;
	encode_null(&copied_identifier_octets, dst + copied_identifier_octets);
	(*copied_octets) += copied_identifier_octets;
}

int encode_rsa_private_key_pkcs8(uint32_t *length, uint8_t **dst, struct s_private_key *key)
{
	uint32_t main_sequence_data_length;
	uint32_t offset;

	// Length
	*length = 3; // Version is 3 octets
	*length += get_rsa_identifier_length();
	*length += get_pkey_octetstring_length(key);
	main_sequence_data_length = *length;
	*length += get_length_length(*length) + 1; // Add the length octets and sequence tag
	*dst = malloc(*length);
	if (!*dst)
		return FT_SSL_FATAL_ERR;

	// Copy data ...
	offset = 0;
	encode_small_tag(&offset, *dst, DER_SEQUENCE);
	encode_length(&offset, (*dst) + offset, main_sequence_data_length);
	encode_small_integer(&offset, (*dst) + offset, 0); // Version = 0
	encode_rsa_identifier(&offset, (*dst) + offset);
	encode_pkey_octetstring(&offset, (*dst) + offset, key);

	return FT_SSL_SUCCESS;
}

int encode_rsa_private_key_pkcs1(uint32_t *length, uint8_t **dst, struct s_private_key *key)
{
	uint32_t offset;

	// Length
	*length = get_pkey_sequence_length(key);
	*dst = malloc(*length);
	if (!*dst)
		return FT_SSL_FATAL_ERR;

	// Copy data ...
	offset = 0;
	encode_pkey_sequence(&offset, *dst, key);
	return FT_SSL_SUCCESS;
}

int encode_rsa_private_key(uint32_t *length, uint8_t **dst, struct s_private_key *key, int pkcs1)
{
	if (pkcs1)
		return encode_rsa_private_key_pkcs1(length, dst, key);
	else
		return encode_rsa_private_key_pkcs8(length, dst, key);
}
