#include <stdio.h>
#include <assert.h>

#include <other_base64.h>
#include <rsa_common_header.h>
#include <phase1.h>
#include <../test/test_utility.h>

const rsaKey_t public_key = {33, 3};
const rsaKey_t private_key = {33, 7};
const keyPair_t key_pair = {public_key, private_key};

void test_print_key() {
    printf("> Starting Test Print Key.\n");

    int saved_stdout;
    FILE* print_key_base64_file = redirect_stdout(&saved_stdout);

    print_key(&public_key);
    fflush(stdout);

    fseek(print_key_base64_file, 0, SEEK_SET);
    char* print_key_output = read_line_from_file(print_key_base64_file);

    restore_stdout(saved_stdout);
    fclose(print_key_base64_file);

    char expected_output[KEY_PRINT_BUFFER_SIZE];
    snprintf(expected_output, sizeof(expected_output), "(n = %lu; e = %lu)\n", public_key.N, public_key.E);

    assert(strcmp(print_key_output, expected_output) == 0);

    free(print_key_output);
}

void test_print_key_pair() {
    printf("> Starting Test Print Key Pair.\n\n");

    int saved_stdout;
    FILE* print_key_base64_file = redirect_stdout(&saved_stdout);

    print_key_pair(&key_pair);
    fflush(stdout);

    fseek(print_key_base64_file, 0, SEEK_SET);
    
    char expected_output[KEY_PRINT_BUFFER_SIZE];

    char* print_key_output = read_line_from_file(print_key_base64_file);
    snprintf(expected_output, KEY_PRINT_BUFFER_SIZE, "Public Key: (n = %lu; e = %lu)\n", public_key.N, public_key.E);
    assert(strcmp(print_key_output, expected_output) == 0);
    free(print_key_output);
    
    print_key_output = read_line_from_file(print_key_base64_file);
    snprintf(expected_output, KEY_PRINT_BUFFER_SIZE, "Private Key: (n = %lu; e = %lu)\n", private_key.N, private_key.E);
    assert(strcmp(print_key_output, expected_output) == 0);
    free(print_key_output);

    restore_stdout(saved_stdout);
    fclose(print_key_base64_file);
}

void test_encrypt_decrypt_message_char_by_char() {
    printf("> Starting Test Encrypt Decrypt Message Char By Char.\n");

    uint8_t message[] = {4};
    uint8_t expected_encrypted_message[] = {31};
    size_t message_length = COUNT(message);

    assert(COUNT(message) == COUNT(expected_encrypted_message));

    uint8_t* output = malloc(message_length);
    if (!output) {
        perror("Failed to allocate memory for output");
        exit(EXIT_FAILURE);
    }

    encrypt_message_char_by_char(message, output, message_length, &public_key);
    assert(memcmp(output, expected_encrypted_message, message_length) == 0);

    decrypt_message_char_by_char(expected_encrypted_message, output, message_length, &private_key);
    assert(memcmp(output, message, message_length) == 0);

    free(output);
}

void test_encrypt_decrypt_file_message_char_by_char() {
    printf("> Starting Test Encrypt Decrypt File Message Char By Char.\n\n");

    uint8_t message[] = {4};
    uint8_t expected_encrypted_message[] = {31};
    size_t message_length = COUNT(message);

    assert(COUNT(message) == COUNT(expected_encrypted_message));
    
    FILE* binary_file = tmpfile();
    if (!binary_file) {
        perror("Failed to create input file using tmpfile");
        exit(EXIT_FAILURE);
    }

    fwrite(&message, sizeof(uint8_t), message_length, binary_file);
    fseek(binary_file, 0, SEEK_SET);

    FILE* base64_file = tmpfile();
    if (!base64_file) {
        perror("Failed to create output file using tmpfile");
        exit(EXIT_FAILURE);
    }

    uint8_t* output = malloc(message_length);
    if (!output) {
        perror("Failed to allocate memory for output");
        exit(EXIT_FAILURE);
    }

    encrypt_decrypt_file_message_char_by_char(binary_file, base64_file, &public_key, true);
    
    fseek(base64_file, 0, SEEK_SET);
    size_t bytes_read = fread(output, sizeof(uint8_t), message_length, base64_file);
    check_fread_error(base64_file, bytes_read, message_length);

    assert(memcmp(output, expected_encrypted_message, message_length) == 0);


    clear_file_content(binary_file);


    encrypt_decrypt_file_message_char_by_char(base64_file, binary_file, &private_key, false);
    
    fseek(binary_file, 0, SEEK_SET);
    bytes_read = fread(output, sizeof(uint8_t), message_length, binary_file);
    check_fread_error(binary_file, bytes_read, message_length);
    
    assert(memcmp(output, message, message_length) == 0);


    free(output);

    fclose(binary_file);
    fclose(base64_file);
}

void test_bytes_to_base64(const uint8_t* message, size_t message_length, const char* expected_output) {
    printf("> Starting Test Bytes To Base64.\n");
    
    size_t encoded_message_length;
    
    char* encoded_message = bytes_to_base64(message, message_length, &encoded_message_length);
    assert(strcmp(encoded_message, expected_output) == 0);

    free(encoded_message);
}

void test_base64_to_binary(const char* encoded_message, const char* expected_output) {
    printf("> Starting Test Base64 To Binary.\n");

    char* binary_string = base64_to_binary(encoded_message);
    assert(strcmp(binary_string, expected_output) == 0);

    free(binary_string);
}

void test_uint32_base64(uint32_t value, const char* expected_output) {
    printf("> Starting Test uint32 To Base64.\n");

    uint8_t message[4];
    message[0] = (value >> 24) & 0xFF;
    message[1] = (value >> 16) & 0xFF;
    message[2] = (value >> 8) & 0xFF;
    message[3] = (value & 0xFF);

    test_bytes_to_base64(message, sizeof(value), expected_output);
}

void test_uint64_base64(uint64_t value, const char* expected_output) {
    printf("> Starting Test uint64 To Base64.\n");

    uint8_t message[8];
    message[0] = (value >> 56) & 0xFF;
    message[1] = (value >> 48) & 0xFF;
    message[2] = (value >> 40) & 0xFF;
    message[3] = (value >> 32) & 0xFF;
    message[4] = (value >> 24) & 0xFF;
    message[5] = (value >> 16) & 0xFF;
    message[6] = (value >> 8) & 0xFF;
    message[7] = value & 0xFF;

    test_bytes_to_base64(message, sizeof(value), expected_output);
}

void test_chars_base64(const char* value, const char* expected_output) {
    printf("> Starting Test Chars To Base64.\n");

    test_bytes_to_base64((uint8_t*) value, strlen(value), expected_output);
}

void test_binary_file_to_base64_file(const uint8_t* message, size_t message_length, const char* expected_output) {
    printf("> Starting Test Binary File To Base64 File.\n\n");
    
    FILE* binary_file = tmpfile();
    if (!binary_file) {
        perror("Failed to create binary file using tmpfile");
        exit(EXIT_FAILURE);
    }

    fwrite(message, sizeof(uint8_t), message_length, binary_file);
    fseek(binary_file, 0, SEEK_SET);

    FILE* base64_file = tmpfile();
    if (!base64_file) {
        perror("Failed to create base64 file using tmpfile");
        exit(EXIT_FAILURE);
    }

    size_t base64_output_size = 4 * ((message_length + 2) / 3);
    char* base64_output = malloc(base64_output_size + 1);
    if (!base64_output) {
        perror("Failed to allocate memory for output using malloc");
        exit(EXIT_FAILURE);
    }

    binary_file_to_base64_file(binary_file, base64_file);
    
    fseek(base64_file, 0, SEEK_SET);
    size_t bytes_read = fread(base64_output, sizeof(char), base64_output_size, base64_file);
    check_fread_error(base64_file, bytes_read, base64_output_size);

    base64_output[base64_output_size] = '\0';

    assert(strcmp(base64_output, expected_output) == 0);

    free(base64_output);

    fclose(binary_file);
    fclose(base64_file);
}

void test_base64_file_to_binary_file(const char* message, const uint8_t* expected_output, size_t expected_output_length) {
    printf("> Starting Test Base64 File To Binary File.\n\n");

    FILE* base64_file = tmpfile();
    if (!base64_file) {
        perror("Failed to create base64 file using tmpfile");
        exit(EXIT_FAILURE);
    }

    fwrite(message, sizeof(char), strlen(message), base64_file);
    fseek(base64_file, 0, SEEK_SET);

    FILE* binary_file = tmpfile();
    if (!binary_file) {
        perror("Failed to create binary file using tmpfile");
        exit(EXIT_FAILURE);
    }

    char* output = malloc(expected_output_length);
    if (!output) {
        perror("Failed to allocate memory for output using malloc");
        exit(EXIT_FAILURE);
    }

    base64_file_to_binary_file(base64_file, binary_file);
    
    fseek(binary_file, 0, SEEK_SET);
    size_t bytes_read = fread(output, sizeof(uint8_t), expected_output_length, binary_file);
    check_fread_error(binary_file, bytes_read, expected_output_length);

    assert(memcmp(output, expected_output, expected_output_length) == 0);

    free(output);

    fclose(base64_file);
    fclose(binary_file);
}

void tests_base64() {
    printf("> Starting Test Bytes To Base64.\n");
    
    uint8_t message[] = {72, 73};
    char* base64_message = "SEk=";
    size_t message_length = COUNT(message);
    
    test_bytes_to_base64(message, message_length, base64_message);

    test_base64_to_binary(base64_message, "0100100001001001"); 
    
    test_uint32_base64(0x12345678, "EjRWeA==");
    test_uint64_base64(0x1234567890ABCDEF, "EjRWeJCrze8=");

    test_chars_base64("HI", base64_message);
    
    test_binary_file_to_base64_file(message, message_length, base64_message);

    test_base64_file_to_binary_file(base64_message, message, message_length);
}

int main(void) {
    printf("> Starting Phase 1 Test\n\n");

    test_print_key();

    test_print_key_pair();

    test_encrypt_decrypt_message_char_by_char();

    test_encrypt_decrypt_file_message_char_by_char();

    tests_base64();

    printf("\n> All Phase 1 Tests Passed!\n");
}