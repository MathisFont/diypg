// fichier de test pour les fonctions de other_base64.c
// gcc -Wall -I../include test_base64.c ../src/other_base64.c -o test_base64
#include "../include/other_base64.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


void test_base64_encode() {
    printf("> Starting Test Base64 Encode.\n");

    const unsigned char* input = (const unsigned char*)"Hello, World!";
    const char* expected_output = "SGVsbG8sIFdvcmxkIQ==";

    size_t output_length;
    char* output = base64_encode(input, strlen((const char*)input), &output_length);
    if (!output) {
        fprintf(stderr, "Error: Failed to encode string in base64.\n");
        exit(EXIT_FAILURE);
    }
    assert(output_length == strlen(expected_output));
    assert(strcmp(output, expected_output) == 0);

    free(output);
}

void test_base64_decode() {
    printf("> Starting Test Base64 Decode.\n");

    const char* input = "SGVsbG8sIFdvcmxkIQ==";
    const char* expected_output = "Hello, World!";

    size_t output_length;
    uint8_t* output = base64_decode(input,strlen(input) ,&output_length);
    if (!output) {
        fprintf(stderr, "Error: Failed to decode string from base64.\n");
        exit(EXIT_FAILURE);
    }
    assert(output_length == strlen(expected_output));
    assert(memcmp(output, expected_output, output_length) == 0);

    free(output);
}

int main(void) {
    test_base64_encode();
    test_base64_decode();
    return 0;
}
