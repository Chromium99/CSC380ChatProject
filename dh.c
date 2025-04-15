#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "dh.h"

mpz_t q, p, g;
size_t qBitlen, pBitlen, qLen, pLen;

int init(const char* fname) {
    mpz_init(q);
    mpz_init(p);
    mpz_init(g);
    FILE* f = fopen(fname, "rb");
    if (!f) {
        fprintf(stderr, "Could not open file 'params'\n");
        return -1;
    }
    int nvalues = gmp_fscanf(f, "q = %Zd\np = %Zd\ng = %Zd", q, p, g);
    fclose(f);
    if (nvalues != 3) {
        printf("Couldn't parse parameter file\n");
        return -1;
    }
    qBitlen = mpz_sizeinbase(q, 2);
    pBitlen = mpz_sizeinbase(p, 2);
    qLen = (qBitlen + 7) / 8;
    pLen = (pBitlen + 7) / 8;
    return 0;
}

int dhGen(mpz_t sk, mpz_t pk) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "Failed to open /dev/urandom\n");
        return -1;
    }
    unsigned char* buf = malloc(qLen + 32);
    fread(buf, 1, qLen + 32, f);
    fclose(f);

    mpz_init(sk);
    mpz_init(pk);
    BYTES2Z(sk, buf, qLen + 32); 
    mpz_mod(sk, sk, q); 
    mpz_powm(pk, g, sk, p);
    free(buf);
    return 0;
}

int dhGenk(dhKey* k) {
    assert(k);
    initKey(k);
    return dhGen(k->SK, k->PK);
}
