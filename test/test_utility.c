#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define LINE_BUFFER_SIZE 256
#define KEY_PRINT_BUFFER_SIZE 128

typedef void (*ElementPrinter) (const void*);

FILE* redirect_stdout(int* saved_stdout_fd) {
    *saved_stdout_fd = dup(STDOUT_FILENO);
    if (*saved_stdout_fd == -1) {
        perror("Failed to duplicate stdout using dup");
        exit(EXIT_FAILURE);
    }

    FILE* temp_file = tmpfile();
    if (temp_file == NULL) {
        perror("Failed to create temporary file using tmpfile");
        exit(EXIT_FAILURE);
    }

    fflush(stdout);
    if(dup2(fileno(temp_file), STDOUT_FILENO) == -1) {
        perror("Failed to redirect stdout using dup2");
        exit(EXIT_FAILURE);
    }

    return temp_file;
}

void restore_stdout(int saved_stdout_fd) {
    if (dup2(saved_stdout_fd, STDOUT_FILENO) == -1) {
        perror("Failed to restore stdout using dup2");
        exit(EXIT_FAILURE);
    }
}

void check_fread_error(FILE *output_file, size_t bytes_read, size_t message_length) {
    if (bytes_read != message_length) {
        if (feof(output_file)) {
            fprintf(stderr, "Reached end of file before reading the expected number of bytes.\n");
        } else if (ferror(output_file)) {
            perror("Error reading from file");
        } else {
            fprintf(stderr, "Unknown error occurred while reading from the file.\n");
        }
        
        exit(EXIT_FAILURE);
    }
}

char* read_line_from_file(FILE* file) {
    if (!file) {
        fprintf(stderr, "Error: Invalid file pointer. The file may not be open.\n");
        exit(EXIT_FAILURE);
    }

    char* line = malloc(LINE_BUFFER_SIZE);
    if (fgets(line, LINE_BUFFER_SIZE, file) == NULL) {
        free(line);

        perror("Failed to read line from the file using fgets");
        exit(EXIT_FAILURE);
    }

    return line;
}

void clear_file_content(FILE *file) {
    int fd = fileno(file);
    
    if (ftruncate(fd, 0) == -1) {
        perror("Failed to truncate the file using ftruncate");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_SET);
}

void print_array(const void* array, size_t length, size_t element_size, ElementPrinter print) {
    printf("Array:\n");
    for (size_t i = 0; i < length; i++) {
        void* element = (char*) array + i * element_size;
        printf("i = %ld: ", i);
        print(element);
    }
    printf("\n");
}

void print_uint8(const void* data) {
    printf("%d\n", *(uint8_t *) data);
}