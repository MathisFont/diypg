#ifndef TEST_UTILITY_H
#define TEST_UTILITY_H

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

#define KEY_PRINT_BUFFER_SIZE 128

typedef void (*ElementPrinter) (const void*);

FILE* redirect_stdout(int* saved_stdout_fd);
void restore_stdout(int saved_stdout_fd);

void check_fread_error(FILE *output_file, size_t bytes_read, size_t message_length);
char* read_line_from_file(FILE* file);
void clear_file_content(FILE *file);

void print_array(const void* array, size_t length, size_t element_size, ElementPrinter print);
void print_uint8(const void* data);

#endif