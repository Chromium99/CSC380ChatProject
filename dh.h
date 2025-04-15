#pragma once
#include <gmp.h>

extern mpz_t q, p, g;
extern size_t qBitlen, pBitlen, qLen, pLen;

int init(const char* fname);
int dhGen(mpz_t sk, mpz_t pk);
int dhGenk(dhKey* k);
