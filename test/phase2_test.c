#include <stdio.h>
#include <stdint.h>
#include <string.h> 
#include <phase2.h>
#include <rsa_common_header.h>
#include <other_base64.h>
#include <../test/test_utility.h>
#include <utility.h>

const rsaKey_t public_key = {609693217117010353, 3};
const rsaKey_t private_key = {609693217117010353, 406462143700129347};

const rsaKey_t public_key_short = {
    .N = 65537,   
    .E = 12708343 
};

void test_bytes_to_uint32() {
    printf("> Starting Test Bytes To uint32.\n");
    
    uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00};
    assert(bytes_to_uint32(bytes) == 0);

    uint8_t bytes_2[] = {0x12, 0x34, 0x56, 0x78};
    assert(bytes_to_uint32(bytes_2) == 0x78563412);

    uint8_t bytes_3[] = {0x78, 0x56, 0x34, 0x12};
    assert(bytes_to_uint32(bytes_3) == 0x12345678);

    uint8_t bytes_4[] = {0xFF, 0xFF, 0xFF, 0xFF};
    assert(bytes_to_uint32(bytes_4) == 0xFFFFFFFF);
}

void test_uint32_to_bytes() {
    printf("> Starting Test uint32 To Bytes.\n");

    uint8_t expected_output[] = {0x78, 0x56, 0x34, 0x12};
    uint8_t* output = uint32_to_bytes(0x12345678);

    assert(memcmp(output, expected_output, COUNT(expected_output)) == 0);
}

void test_puissance_mod_n_gmp() {
    printf("> Starting Test Puissance Mod N GMP.\n");

    mpz_t base;
    mpz_init(base);
    mpz_set_str(base, "235458927092877800", 10);

    unsigned long int expected = 753677707;

    mpz_t result;
    mpz_init(result);

    puissance_mod_n_gmp(base, 84917382905332, 987654321, result);

    assert(mpz_cmp_ui(result, expected) == 0);

    mpz_clear(result);
}

void test_encrypt_block() {
    printf("> Starting Test Encrypt Block.\n");

    mpz_t block;
    mpz_init(block);
    mpz_set_str(block, "77686174", 16);

    mpz_t expected_output;
    mpz_init(expected_output);
    mpz_set_str(expected_output, "225818087037046457", 10);

    mpz_t encrypted_message;
    mpz_init(encrypted_message);
    encrypt_block(block, &public_key, encrypted_message);

    assert(mpz_cmp(encrypted_message, expected_output) == 0);

    mpz_clear(expected_output);
}

void test_decrypt_block() {
    printf("> Starting Test Decrypt Block.\n");

    mpz_t block;
    mpz_init(block);
    mpz_set_str(block, "225818087037046457", 10);

    mpz_t expected_output;
    mpz_init(expected_output);
    mpz_set_str(expected_output, "77686174", 16);

    mpz_t encrypted_message;
    mpz_init(encrypted_message);
    decrypt_block(block, &private_key, encrypted_message);

    assert(mpz_cmp(encrypted_message, expected_output) == 0);

    mpz_clear(expected_output);
}

void test_encrypt_decrypt_message_by_block_from_file() {
    printf("> Starting Test Encrypt Decrypt Message By Block From File.\n");

    uint8_t message[] = {0x77, 0x68, 0x61, 0x74}; 
    size_t message_length = sizeof(message);

    FILE* input_file = tmpfile();
    if (!input_file) {
        perror("Failed to create input file using tmpfile");
        exit(EXIT_FAILURE);
    }
    fwrite(message, 1, message_length, input_file);
    fseek(input_file, 0, SEEK_SET);

    FILE* encrypted_file = tmpfile();
    if (!encrypted_file) {
        perror("Failed to create encrypted file using tmpfile");
        fclose(input_file);
        exit(EXIT_FAILURE);
    }

    encrypt_message_by_block_from_file(input_file, encrypted_file, &public_key);
    fseek(encrypted_file, 0, SEEK_SET);

    FILE* decrypted_file = tmpfile();
    if (!decrypted_file) {
        perror("Failed to create decrypted file using tmpfile");
        fclose(input_file);
        fclose(encrypted_file);
        exit(EXIT_FAILURE);
    }

    decrypt_message_by_block_from_file(encrypted_file, decrypted_file, &private_key);
    fseek(decrypted_file, 0, SEEK_SET);

    size_t decrypted_length;
    uint8_t* decrypted = read_file_per_byte(decrypted_file, &decrypted_length);

    assert(decrypted_length == message_length);
    assert(memcmp(decrypted, message, message_length) == 0);

    free(decrypted);
    fclose(input_file);
    fclose(encrypted_file);
    fclose(decrypted_file);

    printf("Encrypt/Decrypt test passed successfully!\n");
}

char* read_encoded_key_value(FILE* file) {
    char* line = read_line_from_file(file);
    if (!line) {
        return NULL;
    }

    size_t len = strlen(line);
    if (len > 0 && line[len-1] == '\n') {
        line[len-1] = '\0';
    }

    return line;
}

void test_encode_key_base64() {
    printf("> Starting Test Encode Key Base64.\n");

    FILE* output_file = tmpfile();
    if (!output_file) {
        perror("Failed to create output file using tmpfile");
        exit(EXIT_FAILURE);
    }

    encode_key_base64(&public_key_short, output_file);

    fseek(output_file, 0, SEEK_SET);
    
    char* header = read_line_from_file(output_file);
    
    assert(strcmp(header, "RSA PUBLIC KEY (base64 format)\n") == 0);
    free(header);
    
    char* n_value = read_encoded_key_value(output_file);

    assert(strcmp(n_value, "NjU1Mzc=") == 0);
    free(n_value);

    char* e_value = read_encoded_key_value(output_file);

    assert(strcmp(e_value, "MTI3MDgzNDM=") == 0);
    free(e_value);

    fclose(output_file);
    printf("Encode key base64 test completed.\n");
}

void test_convert_encrypted_to_base64() {
    printf("> Starting Test Convert Encrypted To Base64.\n");

    FILE* input_file = tmpfile();
    if (!input_file) {
        perror("Failed to create input file");
        exit(EXIT_FAILURE);
    }

    uint8_t test_data[] = {0x00, 0x11, 0x22, 0x33};
    fwrite(test_data, 1, sizeof(test_data), input_file);
    fseek(input_file, 0, SEEK_SET);

    FILE* output_file = tmpfile();
    if (!output_file) {
        fclose(input_file);
        perror("Failed to create output file");
        exit(EXIT_FAILURE);
    }

    convert_encrypted_to_base64(input_file, output_file);

    fseek(output_file, 0, SEEK_SET);
    char* encoded = read_file_string(output_file);
    assert(strcmp(encoded, "ABEiMw==") == 0);

    free(encoded);
    fclose(input_file);
    fclose(output_file);
}

void test_convert_base64_to_binary() {
    printf("> Starting Test Convert Base64 To Binary.\n");

    FILE* input_file = tmpfile();
    if (!input_file) {
        perror("Failed to create input file");
        exit(EXIT_FAILURE);
    }

    fprintf(input_file, "ABEiMw==");
    fseek(input_file, 0, SEEK_SET);

    FILE* output_file = tmpfile();
    if (!output_file) {
        fclose(input_file);
        perror("Failed to create output file");
        exit(EXIT_FAILURE);
    }

    convert_base64_to_binary(input_file, output_file);

    fseek(output_file, 0, SEEK_SET);
    size_t size;
    uint8_t* decoded = read_file_per_byte(output_file, &size);
    
    uint8_t expected[] = {0x00, 0x11, 0x22, 0x33};
    assert(size == sizeof(expected));
    assert(memcmp(decoded, expected, size) == 0);

    free(decoded);
    fclose(input_file);
    fclose(output_file);
}


int main(void) {
    printf("> Starting Phase 2 Test\n\n");

    test_bytes_to_uint32();
    test_uint32_to_bytes();

    test_puissance_mod_n_gmp();

    test_encrypt_block();
    test_decrypt_block();

    test_encrypt_decrypt_message_by_block_from_file();

    test_encode_key_base64();
    
    test_convert_encrypted_to_base64();
    test_convert_base64_to_binary();
    
    printf("\n> All Phase 2 Tests Passed!\n");
    return 0;
}