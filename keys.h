#pragma once
#include <gmp.h>

#define MAX_NAME 128

typedef struct {
    char name[MAX_NAME+1];
    mpz_t PK;
    mpz_t SK;
} dhKey;

int initKey(dhKey* k);
int writeDH(char* fname, dhKey* k);
int readDH(char* fname, dhKey* k);
int shredKey(dhKey* k);
char* hashPK(dhKey* k, char* hash);
