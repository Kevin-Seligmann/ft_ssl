#include "ft_ssl.h"
#include "ft_asym.h"

/*
	Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)

	PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
										{ PUBLIC-KEY,
										{ PrivateKeyAlgorithms } }

	PrivateKey ::= OCTET STRING
						-- Content varies based on type of key.  The
						-- algorithm identifier dictates the format of
						-- the key.

	PublicKey ::= BIT STRING
						-- Content varies based on type of key.  The
						-- algorithm identifier dictates the format of
						-- the key.
*/

/*
     OneAsymmetricKey ::= SEQUENCE {
       version                   Version,
       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
       privateKey                PrivateKey,
       attributes            [0] Attributes OPTIONAL,
       ...,
       [[2: publicKey        [1] PublicKey OPTIONAL ]],
       ...
     }
*/

/*
   An RSA private key should be represented with the ASN.1 type
   RSAPrivateKey:

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
             otherPrimeInfos   OtherPrimeInfos OPTIONAL
         }
*/

// struct s_private_key {
// 	uint8_t version;
// 	uint64_t modulus;
// 	uint64_t public_exponent;
// 	uint64_t private_exponent;
// 	uint32_t prime_1;
// 	uint32_t prime_2;
// 	uint64_t exponent_1;
// 	uint64_t exponent_2;
// 	uint64_t coefficient;
// };

/*
	Sequence identifier: 0x30
	7, 8: (0 0) = Universal (Bultin ASN.1 type)
	6: (1) = Constructed
	1, 5: (1 0 0 0 0) = sequence tag


	// Sequence length
	8: (1) = Long form
	7-1: How many length octets
	Length octets with the length

	// Sequence content: Integers

	Integer identifier: 0x2
	7, 8: (0 0) = Universal (Bultin ASN.1 type)
	6: (0) = Primitive
	1, 5: (0 0 0 1 0) = Integer tag

	// Integer length:
	8: (0) = Short form
	7-1: 1 to 8 (Depending on size)

	// Integer content:
	Integer on big endian and it's "shortest" form (No 00000000 octets)

	Version = 0; (only 2 primes)
*/

static uint64_t calculate_content_bytes(struct s_private_key *private_key)
{
	uint8_t *buffer;
	uint64_t count;

	count = 0;
	buffer = (uint8_t *) private_key;
	for (uint32_t i = 0; i < sizeof(struct s_private_key); i ++)
		if (buffer[i] != 0)
			count ++;
	return count;
}

static uint8_t *allocate_der_string(struct s_private_key *private_key, uint64_t *der_length)
{
	uint8_t *str;
	uint64_t content_bytes;

	content_bytes = calculate_content_bytes(private_key);
	
	/*
		Sequence length + identifier = 2 +
		(Intenger length + identifier) * number_of_integers = 9 * 2 +
		Number of bytes (content_bytes)
	*/
	*der_length = 2 + 18 + content_bytes;

	str = malloc(*der_length + 1);
	if (str == NULL)
	{
		write_error2("Memory error", strerror(errno));
		return NULL;
	}
	str[*der_length] = 0;
	return str;
}

static void encode_integer32b(uint8_t **dst, uint32_t integer)
{
	uint8_t *buffer;
	uint32_t count;

	buffer = (uint8_t *) &integer;
	for (int i = 3; i > -1; i ++)
	{
		if (buffer[i] == 0)
			break ;
		(*dst) = buffer[i];
		(*dst) ++;
	}
}

static void encode_integer(uint8_t **dst, uint64_t integer)
{
	uint8_t *buffer;

	buffer = (uint8_t *) &integer;
	for (int i = 7; i > -1; i ++)
	{
		if (buffer[i] == 0)
			break ;
		**dst = buffer[i];
		(*dst) ++;
	}
}

static void encode_private_key(struct s_private_key *private_key, uint8_t *dst, uint64_t der_length)
{
	uint64_t sequence_length;

	sequence_length = der_length - 2;
	dst[0] = 0x30;
	dst[1] = sequence_length;
	dst += 2;
	encode_integer(&dst, private_key->version);
	encode_integer(&dst, private_key->modulus);
	encode_integer(&dst, private_key->public_exponent);
	encode_integer(&dst, private_key->private_exponent);
	encode_integer32b(&dst, private_key->prime_1);
	encode_integer32b(&dst, private_key->prime_2);
	encode_integer(&dst, private_key->exponent_1);
	encode_integer(&dst, private_key->exponent_2);
	encode_integer(&dst, private_key->coefficient);
}

static int encode_rsa_private_key(struct der_encoding *enc_data)
{
	struct s_private_key *pkey;

	pkey = (struct s_private_key *) enc_data->data;
}

int der_encoding(struct der_encoding *data)
{
	if (data->operation == ENCODE_RSA_PRIV_KEY)
		return encode_rsa_private_key(data);
	return FT_SSL_SUCCESS;
}
