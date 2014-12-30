#ifndef _POET_H_
#define _POET_HL_

#include <stdint.h>
#include "api.h"
#include "AESLib.h"
#include "aes.h"

#define BLOCKLEN      CRYPTO_NPUBBYTES
#define BLOCKLEN_BITS CRYPTO_NPUBBYTES*8
#define KEYLEN        CRYPTO_KEYBYTES
#define KEYLEN_BITS   KEYLEN*8

#define SUCCESS 0
#define FAIL    1

typedef unsigned char block[BLOCKLEN];

//typedef int boolean;

#ifdef ARC_BIG_ENDIAN
  #define TO_LITTLE_ENDIAN_64(n) bswap_64(n)
  #define TO_LITTLE_ENDIAN_32(n) bswap_32(n)
#else
  #define TO_LITTLE_ENDIAN_64(n) (n)
  #define TO_LITTLE_ENDIAN_32(n) (n)
#endif


struct poet_ctx {

  aes128_ctx_t encdecASM;
  aes128_ctx_t aes_ltASM;
  aes128_ctx_t aes_lbASM;


  block k; /* block cipher key */
  block tm; /* masking keys */
  block l; /* pmac key */
  block lt; /* AXU key top */
  block lb; /* AXU key bottom*/
  block x; /* top chaining value */
  block y; /* buttom chaining value */
  block tau; /* tag computation value */
  uint64_t mlen;
};

#ifdef __cplusplus
extern "C"{
#endif

void keysetup(struct poet_ctx *ctx, const uint8_t key[KEYLEN]);

void process_header(struct poet_ctx *ctx, const uint8_t  *header,
        uint64_t header_len );


void encrypt_block(struct poet_ctx *ctx, const uint8_t plaintext[16],
       uint8_t ciphertext[16]);

void encrypt_final(struct poet_ctx *ctx, const uint8_t *plaintext,
       uint64_t plen, uint8_t *ciphertext, uint8_t tag[BLOCKLEN]);



void decrypt_block(struct poet_ctx *ctx, const uint8_t ciphertext[16],
       uint8_t plaintext[16]);

int decrypt_final(struct poet_ctx *ctx, const uint8_t *ciphertext,
       uint64_t clen, const uint8_t tag[BLOCKLEN],
      uint8_t *plaintext);

void AES_encrypt_wrap(const unsigned char *in, unsigned char *out, const aes128_ctx_t *key);

#ifdef __cplusplus
}
#endif

#endif //  _POET_H_
