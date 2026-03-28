/// \file rsa_header.h
/// \author Vincent Dugat
/// \date janvier 2025
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <stdint.h> // uintX_t et la suite

#define BLOCK_SIZE 4 // en octets
#define MAX_PRIME 18446744073709551557ULL // UINT64_MAX est trop grand sans GMP
// avec GMP on peut gérer de plus grands nombres
#define BLOCK_BASE_64 12 // caractères
#define NAME_MAX_SIZE 32 // caractères

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAXI(a,b) (((a)>(b))?(a):(b))

extern FILE * logfp;

/* Type of a block of data */
typedef uint8_t block_t[BLOCK_SIZE]; // une case par octet

typedef struct tabUint64_s{
 	uint64_t * uint64array;
 	int dim;
} tabUint64_t;

typedef struct rsaKey_s {
	uint64_t N;// modulo
 	uint64_t E;// exposant
} rsaKey_t;

// struct pour définir une paire de clefs
typedef struct keyPair_s {
 	rsaKey_t pubKey; // (C,N)
 	rsaKey_t privKey; //(U,N)
} keyPair_t;

int premier(uint64_t n);

uint64_t puissance_mod_n (uint64_t a, uint64_t e, uint64_t n);

int64_t bezoutRSA(uint64_t a, uint64_t b, int64_t* u, int64_t* v);
void genKeysRabin(rsaKey_t* pubKey, rsaKey_t* privKey, uint64_t max_prime);

#endif
