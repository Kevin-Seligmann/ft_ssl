#include "ft_ssl.h"
#include "ft_asym.h"
#include "ft_encoding.h"

struct integer_sequence 
{
	size_t size;
	uint8_t *str;
};


/*
	PKCS #8. Encoding. https://datatracker.ietf.org/doc/html/rfc5208


	PrivateKeyInfo ::= SEQUENCE {
	version                   Version,
	privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	privateKey                PrivateKey,
	attributes           [0]  IMPLICIT Attributes OPTIONAL }

	Version ::= INTEGER
	PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
	PrivateKey ::= OCTET STRING
	Attributes ::= SET OF Attribute

	Version is 0.
	privateKey is BER encoded RSAPrivateKey
	Attributes might be ignored.



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
		otherPrimeInfos   OtherPrimeInfos OPTIONAL
	}

	Version is an INTEGER 0. (No multi primes).
	otherPrimesInfos is ignored.


	x.509 Private Key Algorithm Identifier. https://datatracker.ietf.org/doc/html/rfc5280
   AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm               OBJECT IDENTIFIER,
        parameters              ANY DEFINED BY algorithm OPTIONAL  }
	Parameters is encoded as NULL

	https://datatracker.ietf.org/doc/html/rfc4055:
    rsaEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 1 }

	https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.1:
	pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
                     rsadsi(113549) pkcs(1) 1 }

*/

#define PKCS8_PRIV_KEY_BEGIN "-----BEGIN PRIVATE KEY-----\n"
#define PKCS8_PRIV_KEY_END "-----END PRIVATE KEY-----\n"

int output_private_key(struct s_genrsa_command *genrsa)
{
	uint8_t *der_encoded_key;
	uint32_t der_encoded_key_length;
	struct s_encoding base64enc;

	encode_rsa_private_key(&der_encoded_key_length, &der_encoded_key, &genrsa->pkey);

	base64enc.flags = FLAG_ENCODE;
	base64enc.input = (char *) der_encoded_key;
	base64enc.input_size = der_encoded_key_length;
	encoding_base64(&base64enc);

	write(STDOUT_FILENO, PKCS8_PRIV_KEY_BEGIN, ft_strlen(PKCS8_PRIV_KEY_BEGIN));
	for (size_t printed_bytes = 0; printed_bytes < base64enc.output_size; printed_bytes += 64)
	{
		if (base64enc.output_size > 64 + printed_bytes)
			write (STDOUT_FILENO, base64enc.output + printed_bytes, 64);
		else
			write (STDOUT_FILENO, base64enc.output + printed_bytes,base64enc.output_size - printed_bytes);
		ft_putchar_fd('\n', STDOUT_FILENO);
	}
	write(STDOUT_FILENO, PKCS8_PRIV_KEY_END, ft_strlen(PKCS8_PRIV_KEY_END));

	return FT_SSL_SUCCESS;	
}
