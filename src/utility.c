#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * Lit un fichier octet par octet
 * @param file Fichier à lire
 * @param data_output_length Pointeur pour la taille des données
 * @return Tableau d'octets alloué dynamiquement
 */
uint8_t* read_file_per_byte(FILE* file, size_t* data_output_length) {
    fseek(file, 0, SEEK_END);
    long file_length = *data_output_length = ftell(file);
    if (file_length < 0) {
        perror("Failed to get file size using ftell");
        exit(EXIT_FAILURE);
    }
    rewind(file);

    uint8_t* data_output = malloc(file_length);
    if (!data_output) {
        perror("Failed to allocate memory for the file's data using malloc");
        exit(EXIT_FAILURE);
    }

    long read_size = fread(data_output, sizeof(uint8_t), file_length, file);
    if (read_size != file_length) {
        free(data_output);

        perror("Failed to read data from file using fread");
        exit(EXIT_FAILURE);
    }

    return data_output;
}

/**
 * Lit un fichier par blocs de 32 bits
 * @param file Fichier à lire
 * @param data_output_length Pointeur pour le nombre de blocs
 * @return Tableau de uint32_t alloué dynamiquement
 */
uint32_t* read_file_per_block(FILE* file, size_t* data_output_length) {
    fseek(file, 0, SEEK_END);
    long file_length = ftell(file);
    if (file_length < 0) {
        perror("Failed to get file size using ftell");
        exit(EXIT_FAILURE);
    }
    rewind(file);

    size_t num_elements = file_length / sizeof(uint32_t);
    uint32_t* data_output = malloc(num_elements * sizeof(uint32_t));
    if (!data_output) {
        perror("Failed to allocate memory for the file's data using malloc");
        exit(EXIT_FAILURE);
    }

    long read_size = fread(data_output, sizeof(uint32_t), num_elements, file);
    if ((size_t)read_size != num_elements) {
        free(data_output);

        perror("Failed to read data from file using fread");
        exit(EXIT_FAILURE);
    }
    
    *data_output_length = num_elements;

    return data_output;
}

/**
 * Lit un fichier texte complet
 * @param file Fichier à lire
 * @return Chaîne de caractères allouée dynamiquement
 */
char* read_file_string(FILE* file) {
    fseek(file, 0, SEEK_END);
    long file_length = ftell(file);
    if (file_length < 0) {
        perror("Failed to get file size using ftell");
        exit(EXIT_FAILURE);
    }
    rewind(file);

    char* string_output = malloc(file_length + 1);
    if (!string_output) {
        perror("Failed to allocate memory for the file's data using malloc");
        exit(EXIT_FAILURE);
    }

    long read_size = fread(string_output, sizeof(char), file_length, file);
    if (read_size != file_length) {
        free(string_output);

        perror("Failed to read data from file using fread");
        exit(EXIT_FAILURE);
    }

    string_output[file_length] = '\0';

    return string_output;
}