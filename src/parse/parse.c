#include "ft_ssl.h"
#include "ft_parse.h"
#include "ft_encryption.h"
#include "ft_hash.h"
#include "ft_encoding.h"
#include "ft_asym.h"

static struct s_command_info commands[] = 
{
	{"MD5", COMM_TYPE_HASH, hash_command, HASH_ALG_MD5, hash_md5},
	{"SHA-224", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA224, hash_sha224},
	{"SHA-256", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA256, hash_sha256},
	{"SHA-384", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA384, hash_sha384},
	{"SHA-512", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA512, hash_sha512},
	{"SHA-512/224", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA512_224, hash_sha512_224},
	{"SHA-512/256", COMM_TYPE_HASH, hash_command, HASH_ALG_SHA512_256, hash_sha512_256},
	{"WHIRLPOOL", COMM_TYPE_HASH, hash_command, HASH_ALG_WHIRLPOOL, hash_whirlpool},
	{"BASE64", COMM_TYPE_ENCODING, encoding_command, ENC_ALG_BASE64, encoding_base64},
	{"DES", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_ECB, des_ecb_command},
	{"DES-ECB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_ECB, des_ecb_command},
	{"DES-CBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_CBC, des_cbc_command},
	{"DES-PCBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_PCBC, des_pcbc_command},
	{"DES-CFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_CFB, des_cfb_command},
	{"DES-OFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_OFB, des_ofb_command},
	{"DES-CTR", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_CTR, des_ctr_command},
	{"DES-EDE", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_ECB, des_ede_ecb_command},
	{"DES-EDE-ECB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_ECB, des_ede_ecb_command},
	{"DES-EDE-CBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_CBC, des_ede_cbc_command},
	{"DES-EDE-PCBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_PCBC, des_ede_pcbc_command},
	{"DES-EDE-CFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_CFB, des_ede_cfb_command},
	{"DES-EDE-OFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_OFB, des_ede_ofb_command},
	{"DES-EDE-CTR", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE_CTR, des_ede_ctr_command},
	{"DES-EDE3", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_ECB, des_ede3_ecb_command},
	{"DES-EDE3-ECB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_ECB, des_ede3_ecb_command},
	{"DES-EDE3-CBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_CBC, des_ede3_cbc_command},
	{"DES-EDE3-PCBC", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_PCBC, des_ede3_pcbc_command},
	{"DES-EDE3-CFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_CFB, des_ede3_cfb_command},
	{"DES-EDE3-OFB", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_OFB, des_ede3_ctr_command},
	{"DES-EDE3-CTR", COMM_TYPE_ENCRYPT, encryption_command, SIM_ENC_ALG_DES_EDE3_CTR, des_ede3_ctr_command},
	{"RSAUTL", COMM_TYPE_RSAUTL, rsautl_command, 0, 0},
	{"RSA", COMM_TYPE_RSA, rsa_command, 0, 0},
	{"GENRSA", COMM_TYPE_GENRSA, genrsa_command, 0, 0},
	{"GENDSA", COMM_TYPE_GENDSA, gendsa_command, 0, 0},
	{"BREAKIT", COMM_TYPE_BREAKIT, breakit_command, 0, 0},
	{"EXTRACTKEY", COMM_TYPE_EXTRACTKEY, extractkey_command, 0, 0},
	{NULL, 0, NULL, 0, NULL}
};

int get_command_type(struct s_command_info *info, char *command)
{
	int ind;

	ft_str_toupper(command);
	ind = 0;
	while (commands[ind].command_name != NULL)
	{
		if (!ft_strcmp(commands[ind].command_name, command))
			break ;
		ind ++;
	}
	if (commands[ind].command_name == NULL)
		return (FT_SSL_FATAL_ERR);
	*info = commands[ind];
	return (FT_SSL_SUCCESS);
}

int parse(struct s_command *command, int *ind, char **argv)
{
	int foo_ret_code = FT_SSL_SUCCESS;

	if (!argv[1])
	{
		write_error("Invalid number of arguments");
		return FT_SSL_FATAL_ERR;
	}
	ft_str_toupper(argv[1]);
	if (!ft_strcmp(argv[1], "HELP"))
	{
		print_help();
		exit (EXIT_SUCCESS);
	}
	if (get_command_type(&(command->meta_info), argv[1]) == FT_SSL_FATAL_ERR){
		write_error2("Unrecognized command", argv[1]);
		ft_putstr_fd("Try 'help' for more information.\n", STDOUT_FILENO);
		return (FT_SSL_FATAL_ERR);
	}
	*ind = 2; // After command
	foo_ret_code = parse_flags(command, ind, argv);
	return (foo_ret_code);
}
