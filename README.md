Work in progress.

## Implemented algorithms

### Hashing
- md5
- SHA2 Family
- Whirlpool

### Symmetric encription

#### Types: DES, EDE and EDE3
#### Cipher block mode: ECB, CBC, PCBC, FCB, OFB, CTR

### Asymmetric encription

- genrsa

## Flags

### Hashing

p - Echoes STDIN to STDOUT and append the checksum to STDOUT
q - Quiet mode
r - Reverse the format of the output
s - Hashes the next string

### Base64

- i - Input file,
- o - Output file
- e - Encode mode (Default)
- d - Decode mode

### Symmetric encription

- i - Input file,
- o - Output file
- e - Encode mode (Default)
- d - Decode mode
- a - Encode/doce in base64
- k - Next argument is key in hex
- p - Next argument is password in ASCII
- s - Argument is salt in hex
- v - Next argument is initialization vector in hex

### Genrsa

- out - Output file
- traditional - PKCS1 (Instead of PCKS8)

### Rsa (Not implemented)

-inform
-outform
-in
-passin
-out
-passout
-des
-text
-noout
-modulus
-check
-pubin
-pubout

### Rsautl (Not implemented)

-in
-out
-inkey
-pubin
-encrypt
-decrypt
-hexdump

### Gendsa (Not implemented)

-out
-passout
-gendes

