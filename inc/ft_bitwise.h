#ifndef BITWISE_H

# define BITWISE_H

# define ROTATE_LEFT_32B(x, b) (((x) << ((b) & 31)) | ((x) >> ((32 - (b)) & 31)))
# define ROTATE_RIGHT_32B(x, b) ROTATE_LEFT_32B(x, 32 - b)

# define ROTATE_LEFT_64B(x, b) (((x) << ((b) & 63)) | ((x) >> ((64 - (b)) & 63)))
# define ROTATE_RIGHT_64B(x, b) ROTATE_LEFT_64B(x, 64 - b)

#endif
