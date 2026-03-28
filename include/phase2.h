#ifndef PHASE_2_H
#define PHASE_2_H

#include <rsa_common_header.h>

#include <gmp.h>

uint32_t bytes_to_uint32(const uint8_t* bytes);
uint8_t* uint32_to_bytes(uint32_t value);

void puissance_mod_n_gmp(mpz_t base, uint64_t exponent, uint64_t modulo, mpz_t result);

uint32_t encrypt_block(mpz_t block, const rsaKey_t* public_key, mpz_t result);
uint32_t decrypt_block(mpz_t block, const rsaKey_t* private_key, mpz_t result);

void encrypt_message_by_block_from_file(FILE* input_file, FILE* output_file, const rsaKey_t* public_key);
void decrypt_message_by_block_from_file(FILE* input_file, FILE* output_file, const rsaKey_t* private_key);

void encode_key_base64(const rsaKey_t* key, FILE* output_file);

void convert_encrypted_to_base64(FILE* input_file, FILE* output_file);
void convert_base64_to_binary(FILE* input_file, FILE* output_file);

#endif