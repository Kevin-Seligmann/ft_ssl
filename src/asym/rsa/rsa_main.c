#include "ft_ssl.h"
#include "ft_asym.h"
/*
	INFORM or OUTFORM ... PEM AND DER

	IN (File or STDIN) (If key is encrypted, ask for password) . PASSIN - Gives password

	OUT (File or STDOUT) (If key is to encrypt, ask for password) (IN != OUT) PASSOUT - Gives passphrase

	DES for des encryption

	TEXT Prints the key components in hexa

	NOOUT Do not print the encoded version of the key (THe PEM | DER key)

	MODULUS Print modulus

	CHECK Check consistency

	PUBIN Read a public key instead of a private key

	PUBOUT Output a public key instead of a private key


*/
int rsa_command(struct s_command *command, int ind, char **argv){return FT_SSL_FATAL_ERR;}
