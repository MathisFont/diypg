#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <utility.h>
#include <rsa_common_header.h>
#include <other_base64.h>

#include <gmp.h>

/**
 * Convertit 4 octets en un entier 32 bits
 * @param bytes Tableau de 4 octets
 * @return Entier 32 bits correspondant
 */
uint32_t bytes_to_uint32(const uint8_t* bytes) {
    if (!bytes) {
        fprintf(stderr, "Error: The bytes array shouldn't be null.\n");
        exit(EXIT_FAILURE);
    }

    return ((uint32_t) bytes[0]) | ((uint32_t) bytes[1] << 8) | ((uint32_t) bytes[2] << 16) | ((uint32_t) bytes[3] << 24);
}

/**
 * Convertit un entier 32 bits en tableau de 4 octets
 * @param value Entier à convertir
 * @return Tableau de 4 octets alloué dynamiquement (à libérer)
 */
uint8_t* uint32_to_bytes(uint32_t value) {
    uint8_t* bytes = malloc(4 * sizeof(uint8_t));
    if (!bytes) {
        perror("Failed to allocate memory for bytes using malloc");
        exit(EXIT_FAILURE);
    }

    bytes[0] = (uint8_t) value & 0xFF;
    bytes[1] = (uint8_t) (value >> 8) & 0xFF;
    bytes[2] = (uint8_t) (value >> 16) & 0xFF;
    bytes[3] = (uint8_t) (value >> 24) & 0xFF;

    return bytes;
}

/**
 * Calcule base^exponent mod modulo en utilisant GMP
 * @param base Nombre de base (mpz_t)
 * @param exponent Exposant
 * @param modulo Modulo
 * @param result Résultat (mpz_t)
 */
void puissance_mod_n_gmp(mpz_t base, uint64_t exponent, uint64_t modulo, mpz_t result) {
    mpz_t e, n;
    
    mpz_init_set_ui(e, exponent);
    mpz_init_set_ui(n, modulo);

    mpz_powm(result, base, e, n);

    mpz_clear(e);
    mpz_clear(n);
}

/**
 * Chiffre un bloc avec RSA
 * @param block Bloc à chiffrer (mpz_t)
 * @param public_key Clé publique RSA
 * @param result Résultat chiffré (mpz_t)
 */
void encrypt_block(mpz_t block, const rsaKey_t* public_key, mpz_t result) {
    puissance_mod_n_gmp(block, public_key->E, public_key->N, result);
}

/**
 * Déchiffre un bloc avec RSA
 * @param block Bloc à déchiffrer (mpz_t)
 * @param private_key Clé privée RSA
 * @param result Résultat déchiffré (mpz_t)
 */
void decrypt_block(mpz_t block, const rsaKey_t* private_key, mpz_t result) {
    puissance_mod_n_gmp(block, private_key->E, private_key->N, result);
}

/**
 * Chiffre un fichier bloc par bloc avec RSA
 * Chaque bloc fait BLOCK_SIZE octets
 * @param input_file Fichier d'entrée
 * @param output_file Fichier de sortie
 * @param public_key Clé publique RSA
 */
void encrypt_message_by_block_from_file(FILE* input_file, FILE* output_file, const rsaKey_t* public_key) {
    size_t message_length = 0;
    uint8_t* message = read_file_per_byte(input_file, &message_length);

    size_t padded_length = ((message_length + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
    uint8_t* padded_message = malloc(padded_length);
    if (!padded_message) {
        free(message);
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(padded_message, message, message_length);

    for(size_t i = message_length; i < padded_length; i++) {
        padded_message[i] = 0;
    }

    fwrite(&message_length, sizeof(size_t), 1, output_file);

    size_t blocks_amount = padded_length / BLOCK_SIZE;

    for (size_t i = 0; i < blocks_amount; i++) {
        uint8_t* block = &padded_message[i * 4];
        uint32_t block_value = bytes_to_uint32(block);
        
        mpz_t block_mpz;
        mpz_init(block_mpz);
        mpz_set_ui(block_mpz, block_value);

        mpz_t result;
        mpz_init(result);
        
        encrypt_block(block_mpz, public_key, result);
        
        gmp_fprintf(output_file, "%Zd\n", result);

        mpz_clear(result);
        mpz_clear(block_mpz);
    }

    free(message);
    free(padded_message);
}

/**
 * Déchiffre un fichier bloc par bloc avec RSA
 * @param input_file Fichier chiffré
 * @param output_file Fichier déchiffré
 * @param private_key Clé privée RSA
 */
void decrypt_message_by_block_from_file(FILE* input_file, FILE* output_file, const rsaKey_t* private_key) {
    size_t original_length;
    if (fread(&original_length, sizeof(size_t), 1, input_file) != 1) {
        fprintf(stderr, "Error: Could not read message length.\n");
        return;
    }

    char line[256];
    size_t bytes_written = 0;
    
    while (fgets(line, sizeof(line), input_file) && bytes_written < original_length) {
        mpz_t encrypted_block;
        mpz_init(encrypted_block);
        mpz_set_str(encrypted_block, line, 10);
        
        mpz_t result;
        mpz_init(result);
        decrypt_block(encrypted_block, private_key, result);
        
        uint32_t decrypted_value = mpz_get_ui(result);
        uint8_t* bytes = uint32_to_bytes(decrypted_value);

        size_t bytes_to_write = MIN(4, original_length - bytes_written);
        fwrite(bytes, sizeof(uint8_t), bytes_to_write, output_file);
        bytes_written += bytes_to_write;
        
        free(bytes);
        mpz_clear(result);
        mpz_clear(encrypted_block);
    }
}

/**
 * Encode une clé publique RSA en base64
 * Format: N et E sur des lignes séparées
 * @param public_key Clé publique à encoder
 * @param output_file Fichier de sortie
 */
void encode_key_base64(const rsaKey_t* public_key, FILE* output_file) {
    fprintf(output_file, "RSA PUBLIC KEY (base64 format)\n");
    
    char str_n[64] = {0}, str_e[64] = {0};
    
    snprintf(str_n, sizeof(str_n), "%lu", public_key->N);
    snprintf(str_e, sizeof(str_e), "%lu", public_key->E);
    
    size_t output_length_n, output_length_e;
    char* encoded_n = base64_encode((unsigned char*)str_n, strlen(str_n), &output_length_n);
    char* encoded_e = base64_encode((unsigned char*)str_e, strlen(str_e), &output_length_e);

    fprintf(output_file, "%s\n", encoded_n);
    fprintf(output_file, "%s\n", encoded_e);

    free(encoded_n);
    free(encoded_e);
}

/**
 * Convertit un fichier chiffré en base64
 * @param input_file Fichier chiffré
 * @param output_file Fichier encodé en base64
 */
void convert_encrypted_to_base64(FILE* input_file, FILE* output_file) {
    size_t file_size;
    uint8_t* encrypted_data = read_file_per_byte(input_file, &file_size);

    size_t base64_length;
    char* base64_data = base64_encode(encrypted_data, file_size, &base64_length);
    if (!base64_data) {
        perror("Failed to encode data in base64");
        free(encrypted_data);
        exit(EXIT_FAILURE);
    }
    
    fprintf(output_file, "%s", base64_data);

    free(encrypted_data);
    free(base64_data);
}

/**
 * Convertit un fichier base64 en binaire
 * @param input_file Fichier base64
 * @param output_file Fichier binaire
 */
void convert_base64_to_binary(FILE* input_file, FILE* output_file) {
    char* base64_data = read_file_string(input_file);

    size_t binary_length;
    unsigned char* binary_data = base64_decode(base64_data, strlen(base64_data), &binary_length);
    if (!binary_data) {
        perror("Failed to decode base64 data");
        free(base64_data);
        exit(EXIT_FAILURE);
    }
    
    fwrite(binary_data, 1, binary_length, output_file);

    free(base64_data);
    free(binary_data);
}
