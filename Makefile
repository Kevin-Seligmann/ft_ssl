VPATH = src src/utils src/hash src/encryption src/encoding src/parse src/encryption/algorithms \
	src/asym/extractkey src/asym/gendsa src/asym/genrsa src/asym/rsa src/asym/rsautl src/asym/breakit \
	src/asym/der_encoding

OBJ_MAIN =  main.o parse.o write_errors.o parse_flags.o parse_arg_getter.o write_userinfo.o

OBJ_LIB = ft_putstr_fd.o ft_str_toupper.o ft_strcmp.o ft_toupper.o ft_strlen.o \
			ft_putchar_fd.o ft_strdup.o ft_strjoin.o ft_read_file.o ft_memset.o ft_memcpy.o \
			ft_strchr.o ft_bitwise.o

OBJ_HASH = hash_main.o hash_md5.o hash_whirlpool.o hash_preprocess.o hash_operations.o \
			hash_sha256.o hash_sha512.o hash_printing.o

OBJ_ENCODING = encoding_base64.o encoding_main.o encode_base64.o decode_base64.o

OBJ_CRYPT = encrypt_getkey.o encrypt_getsalt.o encrypt_main.o encrypt_utils.o encrypt_getsourcetext.o \
			encrypt_base64.o encrypt_getiv.o des_ecb.o des_block_cipher.o key_schedule.o \
			encrypt_output.o

OBJ_ASYM = breakit_main.o extractkey_main.o gendsa_main.o genrsa_main.o rsa_main.o rsautl_main.o \
			genrsa_prime.o genrsa_output.o der_encoding.o

# Files
OBJ = $(OBJ_MAIN) $(OBJ_LIB) $(OBJ_HASH) $(OBJ_ENCODING) $(OBJ_CRYPT) $(OBJ_ASYM)

# Target
NAME = ft_ssl

# Project
PROJ = ft_ssl

# Directories
OBJ_DIR = obj

INC_DIR = inc

OBJ_PATH = $(addprefix $(OBJ_DIR)/, $(OBJ))

DEPS = $(OBJ_PATH:.o=.d)

# Include
INCLUDES = -I./$(INC_DIR)

# Flags
FLAGS = -Wall -Wextra -Werror -g -Wno-unused

# Compiler
CC = cc

# Colors
YELLOW = "\e[33m"
GREEN = "\e[32m"
NO_COLOR = "\e[0m"

# Linking
all: $(OBJ_DIR) $(NAME)

$(NAME): $(OBJ_PATH) Makefile
	@$(CC) $(FLAGS) $(OBJ_PATH) -o $(NAME) -lm -lcrypto -lssl
	@echo $(YELLOW)$(PROJ) - Creating exec:$(NO_COLOR) $(NAME)

# Compilation
$(OBJ_DIR)/%.o:%.c
	@$(CC) -MMD $(INCLUDES) $(FLAGS) -c $< -o $@
	@echo $(YELLOW)$(PROJ) - Compiling object file:$(NO_COLOR) $(notdir $@)

# Utils
-include $(DEPS)

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

clean:
	@rm -rf $(OBJ_DIR)
	@echo $(YELLOW)$(PROJ) - Removing:$(NO_COLOR) Object and dependency files

fclean: clean
	@rm -rf $(NAME) $(NAME_B)
	@echo $(YELLOW)$(PROJ) - Removing:$(NO_COLOR) $(NAME) $(NAME_B)

re: fclean all

.PHONY: clean fclean all re $(OBJ_DIR)
