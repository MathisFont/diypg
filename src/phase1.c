#include <stdio.h>

#include <utility.h>
#include <rsa_common_header.h>
#include <other_base64.h>

/**
 * Affiche une clé RSA (N et E)
 */
void print_key(const rsaKey_t* key) {
    printf("(n = %lu; e = %lu)\n", key->N, key->E);
}

/**
 * Affiche une paire de clés RSA (publique et privée)
 */
void print_key_pair(const keyPair_t* key_pair) {
    printf("Public Key: ");
    print_key(&key_pair->pubKey);
    
    printf("Private Key: ");
    print_key(&key_pair->privKey);
}

/**
 * Chiffre un message caractère par caractère avec RSA
 * @param message Message à chiffrer
 * @param encrypted_message Buffer pour le message chiffré
 * @param len Longueur du message
 * @param public_key Clé publique RSA
 */
void encrypt_message_char_by_char(const uint8_t* message, uint8_t* encrypted_message, size_t len, const rsaKey_t* public_key) {
    if (public_key->N >= (1 << 16)) {
        fprintf(stderr, "Error: Product overflow. The modulo should be inferior to 2¹⁶.\n");
        exit(EXIT_FAILURE);
    }
    
    for (size_t i = 0; i < len; i++) {
        encrypted_message[i] = puissance_mod_n(message[i], public_key->E, public_key->N);
    }
}

/**
 * Déchiffre un message caractère par caractère avec RSA
 * @param encrypted_message Message chiffré à déchiffrer
 * @param decrypted_message Buffer pour le message déchiffré
 * @param len Longueur du message
 * @param private_key Clé privée RSA
 */
void decrypt_message_char_by_char(const uint8_t* encrypted_message, uint8_t* decrypted_message, size_t len, const rsaKey_t* private_key) {
    for (size_t i = 0; i < len; i++) {
        decrypted_message[i] = puissance_mod_n(encrypted_message[i], private_key->E, private_key->N);
    }
}

/**
 * Chiffre ou déchiffre un fichier caractère par caractère
 * @param input_file Fichier d'entrée
 * @param output_file Fichier de sortie
 * @param key Clé RSA (publique pour le chiffrement, privée pour le déchiffrement)
 * @param encrypt Indique si l'on chiffre (true) ou déchiffre (false)
 */
void encrypt_decrypt_file_message_char_by_char(FILE* input_file, FILE* output_file, const rsaKey_t* key, bool encrypt) {
    size_t message_length = 0;
    uint8_t* message = read_file_per_byte(input_file, &message_length);

    uint8_t* processed_message = malloc(message_length);
    if (encrypt) {
        encrypt_message_char_by_char(message, processed_message, message_length, key);
    } else {
        decrypt_message_char_by_char(message, processed_message, message_length, key);
    }

    fwrite(processed_message, sizeof(uint8_t), message_length, output_file);

    free(message);
    free(processed_message);
}

/**
 * Convertit des données binaires en base64
 * @return Chaîne base64 allouée dynamiquement (à libérer)
 */
char* bytes_to_base64(const uint8_t* data, size_t data_length, size_t* encoded_data_length) {
    char* encoded_data = base64_encode(data, data_length, encoded_data_length);
    
    return encoded_data;
}

/**
 * Convertit un fichier binaire en base64
 * Lit le fichier binaire et écrit sa représentation base64
 */
void binary_file_to_base64_file(FILE* binary_file, FILE* base64_file) {
    size_t binaries_length = 0;
    uint8_t* binaries = read_file_per_byte(binary_file, &binaries_length);

    size_t encoded_data_length = 0;
    char* encoded_data = bytes_to_base64(binaries, binaries_length, &encoded_data_length);

    fwrite(encoded_data, sizeof(uint8_t), encoded_data_length, base64_file);

    free(binaries);
    free(encoded_data);
}

/**
 * Convertit un fichier base64 en binaire
 * Lit le fichier base64 et écrit les données binaires correspondantes
 */
void base64_file_to_binary_file(FILE* base64_file, FILE* binary_file) {
    char* encoded_data = read_file_string(base64_file);

    size_t binaries_length = 0;
    uint8_t* binaries = base64_decode(encoded_data, strlen(encoded_data), &binaries_length);

    fwrite(binaries, sizeof(uint8_t), binaries_length, binary_file);

    free(binaries);
    free(encoded_data);
}