#ifndef PHASE_1_H
#define PHASE_1_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <rsa_common_header.h>

void print_key(const rsaKey_t* key);
void print_key_pair(const keyPair_t* key_pair);

void encrypt_message_char_by_char(const uint8_t* message, uint8_t* encrypted_message, size_t len, const rsaKey_t* public_key);
void decrypt_message_char_by_char(const uint8_t* encrypted_message, uint8_t* decrypted_message, size_t len, const rsaKey_t* private_key);

void encrypt_decrypt_file_message_char_by_char(FILE* input_file_path, FILE* output_file_path, const rsaKey_t* key, bool encrypt);

char* bytes_to_base64(const uint8_t* data, size_t data_length, size_t* encoded_data_length);
char* base64_to_binary(const char* data);

//void convert_file_base64(FILE* input_file, FILE* output_file, bool encode);

void binary_file_to_base64_file(FILE* binary_file, FILE* base64_file);
void base64_file_to_binary_file(FILE* base64_file, FILE* binary_file);

#endif