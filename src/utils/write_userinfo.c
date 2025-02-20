#include "ft_ssl.h"


// static struct s_flag_option hash_options[] = 
// {
// 	{"p", HASH_FLAG_APPEND, COMM_TYPE_HASH, 0, 0, "Echoes STDIN to STDOUT and append the checksum to STDOUT"},
// 	{"q", HASH_FLAG_QUIET, COMM_TYPE_HASH, 0, 0, "Quiet mode"},
// 	{"r", HASH_FLAG_REVERSE, COMM_TYPE_HASH, 0, 0, "Reverse the format of the output"},
// 	{"s", HASH_FLAG_STRING_INPUT, COMM_TYPE_HASH, 1, get_s_opt_argument, "Hashes the next string"},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option encoding_options[] = 
// {
// 	{"i", FLAG_INPUTFILE, COMM_TYPE_ENCODING, 1, get_input_file_argument, "Input file"},
// 	{"o", FLAG_OUTPUTFILE, COMM_TYPE_ENCODING, 1, get_output_file_argument, "Output file"},
// 	{"e", FLAG_ENCODE, COMM_TYPE_ENCODING, 0, 0, "Encode mode (Default)"},
// 	{"d", FLAG_DECODE, COMM_TYPE_ENCODING, 0, 0, "Decode mode"},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option crypt_options[] = 
// {
// 	{"i", FLAG_INPUTFILE, COMM_TYPE_ENCRYPT, 1, get_input_file_argument, "Input file"},
// 	{"o", FLAG_OUTPUTFILE, COMM_TYPE_ENCRYPT, 1, get_output_file_argument, "Output file"},
// 	{"e", FLAG_ENCODE, COMM_TYPE_ENCRYPT, 0, 0, "Encode mode (Default)"},
// 	{"d", FLAG_DECODE, COMM_TYPE_ENCRYPT, 0, 0, "Decode mode"},
// 	{"a", FLAG_BASE64_ENCRYPTION, COMM_TYPE_ENCRYPT, 0, 0, "Encode/doce in base64"},
// 	{"k", FLAG_FLAG_KEY, COMM_TYPE_ENCRYPT, 1, get_crypt_key_argument, "Next argument is key in hex"},
// 	{"p", FLAG_PASSWORD, COMM_TYPE_ENCRYPT, 1, get_crypt_pass_argument, "Next argument is password in ASCII"},
// 	{"s", FLAG_SALT, COMM_TYPE_ENCRYPT, 1, get_crypt_salt_argument, "Targument is salt in hex"},
// 	{"v", FLAG_VECTOR, COMM_TYPE_ENCRYPT, 1, get_crypt_vector_argument, "Next argument is initialization vector in hex"},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option genrsa_options[] = 
// {
// 	{"out", FLAG_OUTPUTFILE, COMM_TYPE_GENRSA, 1, get_output_file_argument, "Output file"},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option rsa_options[] = 
// {
// 	{"inform", FLAG_INFORM, COMM_TYPE_RSA, 1, get_inform_argument, ""},
// 	{"outform", FLAG_OUTFORM, COMM_TYPE_RSA, 1, get_outform_argument, ""},
// 	{"in", FLAG_INPUTFILE, COMM_TYPE_RSA, 1, get_input_file_argument, ""},
// 	{"passin", FLAG_PASSIN, COMM_TYPE_RSA, 1, get_passin_argument, ""},
// 	{"out", FLAG_OUTPUTFILE, COMM_TYPE_RSA, 1, get_output_file_argument, ""},
// 	{"passout", FLAG_PASSOUT, COMM_TYPE_RSA, 1, get_passout_argument, ""},
// 	{"des", FLAG_DES, COMM_TYPE_RSA, 0, 0, ""},
// 	{"text", FLAG_TEXT, COMM_TYPE_RSA, 0, 0, ""},
// 	{"noout", FLAG_NOOUT, COMM_TYPE_RSA, 0, 0, ""},
// 	{"modulus", FLAG_MODULUS, COMM_TYPE_RSA, 0, 0, ""},
// 	{"check", FLAG_CHECK, COMM_TYPE_RSA, 0, 0, ""},
// 	{"pubin", FLAG_PUBIN, COMM_TYPE_RSA, 0, 0, ""},
// 	{"pubout", FLAG_POBOUT, COMM_TYPE_RSA, 0, 0, ""},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option rsautl_options[] = 
// {
// 	{"in", FLAG_INPUTFILE, COMM_TYPE_RSAUTL, 1, get_input_file_argument, ""},
// 	{"out", FLAG_OUTPUTFILE, COMM_TYPE_RSAUTL, 1, get_output_file_argument, ""},
// 	{"inkey", FLAG_FLAG_KEY, COMM_TYPE_RSAUTL, 1, get_crypt_key_argument, ""},
// 	{"pubin", FLAG_PUBIN, COMM_TYPE_RSAUTL, 0, 0, ""},
// 	{"encrypt", FLAG_ENCODE, COMM_TYPE_RSAUTL, 0, 0, ""},
// 	{"decrypt", FLAG_DECODE, COMM_TYPE_RSAUTL, 0, 0, ""},
// 	{"hexdump", FLAG_HEXDUMP, COMM_TYPE_RSAUTL, 0, 0, ""},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option gendsa_options[] = 
// {
// 	{"out", FLAG_OUTPUTFILE, COMM_TYPE_GENDSA, 1, get_output_file_argument, ""},
// 	{"passout", FLAG_PASSOUT, COMM_TYPE_GENDSA, 1, get_passout_argument, ""},
// 	{"gendes", FLAG_GENDES, COMM_TYPE_GENDSA, 0, 0, ""},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option breakit_options[] = 
// {
// 	{"k", FLAG_KEYSIZE, COMM_TYPE_BREAKIT, 1, get_keysize_argument, ""},
// 	{"a", FLAG_ALGO, COMM_TYPE_BREAKIT, 1, get_algo_argument, ""},
// 	{"p", FLAG_PLAINTEXT, COMM_TYPE_BREAKIT, 0, 0, ""},
// 	{0, 0, 0, 0, NULL, NULL},
// };

// static struct s_flag_option extractkey_options[] = 
// {
// 	{"k", FLAG_KEYSIZE, COMM_TYPE_EXTRACTKEY, 1, get_keysize_argument, ""},
// 	{"a", FLAG_ALGO, COMM_TYPE_EXTRACTKEY, 1, get_algo_argument, ""},
// 	{"p", FLAG_PLAINTEXT, COMM_TYPE_EXTRACTKEY, 0, 0, ""},
// 	{0, 0, 0, 0, NULL, NULL},
// };

void print_help()
{
	ft_putstr_fd("HASH COMMANDS\n", STDOUT_FILENO);
	ft_putstr_fd("\tMD5\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-224\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-256\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-384\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-512\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-512/224\n", STDOUT_FILENO);
	ft_putstr_fd("\tSHA-512/256\n", STDOUT_FILENO);
	ft_putstr_fd("\tWHIRLPOOL\n", STDOUT_FILENO);
	//print_hash_usage();

	ft_putstr_fd("\nBASE64 COMMANDS\n", STDOUT_FILENO);
	ft_putstr_fd("\tBASE64\n", STDOUT_FILENO);
	//print_base64_usage();

	ft_putstr_fd("\nSYMMETRIC ENCRIPTION COMMANDS\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-ECB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-CBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-PCBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-CFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-OFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-CTR\n", STDOUT_FILENO);
	//print_symm_usage();

	ft_putstr_fd("\tDES-EDE\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-ECB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-CBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-PCBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-CFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-OFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE-CTR\n", STDOUT_FILENO);

	ft_putstr_fd("\tDES-EDE3\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-ECB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-CBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-PCBC\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-CFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-OFB\n", STDOUT_FILENO);
	ft_putstr_fd("\tDES-EDE3-CTR\n", STDOUT_FILENO);

	ft_putstr_fd("\nASYMMETRIC ENCRIPTION COMMANDS\n", STDOUT_FILENO);
	ft_putstr_fd("\tGENRSA\n", STDOUT_FILENO);
	//print_asymm_usage();

	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);
	// ft_putstr_fd("\n", STDOUT_FILENO);

	// {"RSAUTL", COMM_TYPE_RSAUTL, rsautl_command, 0, 0},
	// {"RSA", COMM_TYPE_RSA, rsa_command, 0, 0},
	// {"GENDSA", COMM_TYPE_GENDSA, gendsa_command, 0, 0},
	// {"BREAKIT", COMM_TYPE_BREAKIT, breakit_command, 0, 0},
	// {"EXTRACTKEY", COMM_TYPE_EXTRACTKEY, extractkey_command, 0, 0},
}
