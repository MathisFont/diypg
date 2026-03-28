#ifndef UTILITY_H
#define UTILITY_H

#include <stdint.h>

uint8_t* read_file_per_byte(FILE* file, size_t* data_output_length);
uint32_t* read_file_per_block(FILE* file, size_t* data_output_length);

char* read_file_string(FILE* file);

#endif