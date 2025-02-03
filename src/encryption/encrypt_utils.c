#include "ft_ssl.h"
#include "ft_encryption.h"

int get_cipher_mode(unsigned int alg)
{
	switch(alg)
	{
		case SIM_ENC_ALG_DES_ECB:
		case SIM_ENC_ALG_DES_EDE_ECB: 
		case SIM_ENC_ALG_DES_EDE3_ECB: return ECB_MODE;
		case SIM_ENC_ALG_DES_CBC: 
		case SIM_ENC_ALG_DES_EDE_CBC: 
		case SIM_ENC_ALG_DES_EDE3_CBC: return CBC_MODE;
		case SIM_ENC_ALG_DES_PCBC: 
		case SIM_ENC_ALG_DES_EDE_PCBC: 
		case SIM_ENC_ALG_DES_EDE3_PCBC: return PCBC_MODE;
		case SIM_ENC_ALG_DES_CFB: 
		case SIM_ENC_ALG_DES_EDE_CFB: 
		case SIM_ENC_ALG_DES_EDE3_CFB: return CFB_MODE;
		case SIM_ENC_ALG_DES_OFB: 
		case SIM_ENC_ALG_DES_EDE_OFB: 
		case SIM_ENC_ALG_DES_EDE3_OFB: return OFB_MODE;
		case SIM_ENC_ALG_DES_CTR: 
		case SIM_ENC_ALG_DES_EDE_CTR: 
		case SIM_ENC_ALG_DES_EDE3_CTR: return CTR_MODE;
	}
	return 0;
}

int get_encryption_mode(unsigned int alg)
{
	if (alg >= SIM_ENC_ALG_DES_ECB && alg < SIM_ENC_ALG_DES_EDE_ECB)
		return DES;
	else if (alg >= SIM_ENC_ALG_DES_EDE_ECB && alg < SIM_ENC_ALG_DES_EDE3_ECB)
		return DES_EDE;
	else
		return DES_EDE3;
}

int get_key_length(unsigned int encryption_mode)
{
	switch (encryption_mode)
	{
		case DES: return SINGLE_DES_KEYLEN;
		case DES_EDE: return SINGLE_DES_KEYLEN * 2;
		case DES_EDE3: return SINGLE_DES_KEYLEN * 3;
	}
	return SINGLE_DES_KEYLEN;
}

void copy_w_truncation_or_padding(char *dest, char *source, size_t dest_len, size_t source_len)
{
	if (source_len >= dest_len)
		ft_memcpy(dest, source, source_len);
	else
	{
		ft_memcpy(dest, source, source_len);
		ft_memset(dest + source_len, 0, dest_len - source_len);
	}
}

static int hex_c_to_int(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return 0;
}

void copy_hexa(uint8_t *dest, char *source, size_t dest_len, size_t source_len)
{
	int low_nibble;
	int high_nibble;
	size_t ind;
	size_t src_ind;

	if (source_len < dest_len * 2)
		write_error("Hex string too short, padding with 0s to length");
	if (source_len > dest_len * 2)
		write_error("Hex string too long, ignoring excess");
	ind = 0;
	while (ind < dest_len)
	{
		src_ind = ind * 2;
		low_nibble = 0;
		high_nibble = 0;
		if (src_ind < source_len)
			high_nibble = hex_c_to_int(source[src_ind]);
		if (src_ind + 1 < source_len)
			low_nibble =  hex_c_to_int(source[src_ind + 1]);
		dest[ind] = (high_nibble << 4) | (low_nibble & 0xFF);
		ind ++;
	}
}


int is_hexa(char *str, size_t size)
{
	size_t ind;

	ind = 0;
	while (ind < size)
	{
		if (!((str[ind] >= 'a' && str[ind] <= 'z') \
			|| (str[ind] >= 'A' && str[ind] <= 'Z') \
			|| (str[ind] >= '0' && str[ind] <= '9')))
			return 0;
		ind ++;
	}
	return 1;
}

uint64_t stohex(char *str)
{
	return 0;
}
