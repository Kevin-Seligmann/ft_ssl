# include "ft_ssl.h"
# include "ft_bitwise.h"

uint32_t rotate_right_32bits(int rotation_size, uint32_t word)
{
	return (word >> rotation_size) | (word << (32 - rotation_size));
}
uint64_t rotate_right_64bits(int rotation_size, uint64_t word)
{
	return (word >> rotation_size) | (word << (64 - rotation_size));
}

// 256 family operators
uint32_t ch_32b(uint32_t x, uint32_t y, uint32_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint32_t maj_32b(uint32_t x, uint32_t y, uint32_t z)
{
	return (((x & y) ^ (x & z)) ^ (y & z));
}

uint32_t sum_256_0(uint32_t x)
{
	return ((rotate_right_32bits(2, x) ^ rotate_right_32bits(13, x)) ^ rotate_right_32bits(22, x));
}

uint32_t sum_256_1(uint32_t x)
{
	return ((rotate_right_32bits(6, x) ^ rotate_right_32bits(11, x)) ^ rotate_right_32bits(25, x));
}

uint32_t sigma_256_0(uint32_t x)
{
	return (rotate_right_32bits(7, x) ^ rotate_right_32bits(18, x)) ^  ((uint32_t)(x >> 3));
}

uint32_t sigma_256_1(uint32_t x)
{
	return (rotate_right_32bits(17, x) ^ rotate_right_32bits(19, x)) ^ ((uint32_t)(x >> 10));
}

// 512 family operators
uint64_t ch_64b(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ ((~x) & z));
}

uint64_t maj_64b(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x & y) ^ (x & z) ^ (y & z));
}

uint64_t sum_512_0(uint64_t x)
{
	return rotate_right_64bits(28, x) ^ rotate_right_64bits(34, x) ^ rotate_right_64bits(39, x);
}

uint64_t sum_512_1(uint64_t x)
{
	return rotate_right_64bits(14, x) ^ rotate_right_64bits(18, x) ^ rotate_right_64bits(41, x);
}

uint64_t sigma_512_0(uint64_t x)
{
	return rotate_right_64bits(1, x) ^ rotate_right_64bits(8, x) ^ (x >> 7);
}

uint64_t sigma_512_1(uint64_t x)
{
	return rotate_right_64bits(19, x) ^ rotate_right_64bits(61, x) ^ (x >> 6);
}
