#include <string.h>

#include "poet.h"
#include "gf_mul.h"


#ifdef REDUCED_ROUNDS
  #define TOP_HASH     AES_encrypt_4_wrap(ctx->x, ctx->x, (&ctx->aes_ltASM))
  #define BOTTOM_HASH  AES_encrypt_4_wrap(ctx->y, ctx->y, (&ctx->aes_lbASM))  

#else
  #define TOP_HASH     AES_encrypt_wrap(ctx->x, ctx->x, (&ctx->aes_ltASM))
  #define BOTTOM_HASH  AES_encrypt_wrap(ctx->y, ctx->y, (&ctx->aes_lbASM))

#endif

void AES_encrypt_wrap(const unsigned char *in, unsigned char *out, const aes128_ctx_t *key)
{
  memcpy(out, in, BLOCKLEN);
  aes128_enc(out, key);
}

void AES_decrypt_wrap(const unsigned char *in, unsigned char *out, const aes128_ctx_t *key)
{
  memcpy(out, in, BLOCKLEN);
  aes128_dec(out, key);
}

void AES_encrypt_4_wrap(const unsigned char *in, unsigned char *out, const aes128_ctx_t *key)
{
  memcpy(out, in, BLOCKLEN);
  aes128_4_enc(out, key);
}

void keysetup(struct poet_ctx *ctx, const uint8_t key[KEYLEN_BITS]){

  uint8_t ctr[BLOCKLEN];
  aes128_ctx_t enc;

  memset(ctx->tau,0,BLOCKLEN);
  memset(ctr,0, BLOCKLEN);

  /* Generate block cipher key */
  aes128_init(key, &enc);
  AES_encrypt_wrap(ctr, ctx->k,  &enc);

  aes128_init(ctx->k, &ctx->encdecASM);

  /* Generate header key */
  ctr[BLOCKLEN-1]+=1; AES_encrypt_wrap(ctr, ctx->l,  &enc);


  /* Generate almost XOR universal hash function keys */
  ctr[BLOCKLEN-1]+=1; AES_encrypt_wrap(ctr, ctx->lt,  &enc);
  ctr[BLOCKLEN-1]+=1; AES_encrypt_wrap(ctr, ctx->lb,  &enc);
  aes128_init(ctx->lt, &ctx->aes_ltASM);
  aes128_init(ctx->lb, &ctx->aes_lbASM);


  /* Generate tag masking keys */
  ctr[BLOCKLEN-1]+=1; AES_encrypt_wrap(ctr, ctx->tm,  &enc);
}


/***************************************************************************/
/************************* XOR BLOCKS **************************************/
/***************************************************************************/


inline void xor_block(uint8_t *c, const uint8_t  *a, const uint8_t  *b)
{
  unsigned int i;
  for(i=0; i<BLOCKLEN;i++) c[i] = a[i] ^ b[i];
}



/***************************************************************************/
/********************* Process Header **************************************/
/***************************************************************************/


void process_header(struct poet_ctx *ctx, const uint8_t  *header,
        uint64_t header_len)
{
  block mask;
  block factor;
  block in;
  block out;
  block product;
  uint64_t offset=0;

  ctx->mlen=0;
  memset(factor,0,BLOCKLEN);
  memset(product,0,BLOCKLEN);
  memset(mask,0,BLOCKLEN);
  memset(ctx->tau,0,BLOCKLEN);

  product[0] = 0x80; // since 1000 0000 = 1
  factor[0]  = 0x40; // since 0100 0000 = 2

  while(header_len > BLOCKLEN)
    {
      gf_mul(mask, product, ctx->l);
      xor_block(in,header+offset,mask);
      AES_encrypt_wrap(in, out, &(ctx->encdecASM));
      xor_block(ctx->tau,out,ctx->tau);

      offset += BLOCKLEN;
      header_len -= BLOCKLEN;

      gf_mul(product,product,factor);
    }

  /* LASTBLOCK */
  if(header_len < 16)
    {
      factor[0]=0xA0; // 1010 0000 = 5 in Big Endian
      memset(in,0,BLOCKLEN);
      memcpy(in,header+offset,header_len);
      in[header_len]=0x80;
    }
  else
    {
      factor[0]=0xC0; // 1100 0000 = 3 in Big Endian
      memcpy(in,header+offset,BLOCKLEN);
    }

  gf_mul(product,product,factor);
  gf_mul(mask,product,ctx->l);
  xor_block(in,mask,in);

  xor_block(in,in,ctx->tau);
  AES_encrypt_wrap(in, ctx->tau, &(ctx->encdecASM));

  memcpy(ctx->x, ctx->tau, BLOCKLEN);
  memcpy(ctx->y, ctx->tau, BLOCKLEN);
}



/***************************************************************************/
/********************* Encrypt block ***************************************/
/***************************************************************************/

void encrypt_block(struct poet_ctx *ctx, const uint8_t plaintext[16],
       uint8_t ciphertext[16])
{
  block tmp;
  TOP_HASH;
  xor_block(ctx->x, plaintext,ctx->x);

  AES_encrypt_wrap(ctx->x, tmp, &(ctx->encdecASM));

  BOTTOM_HASH;
  xor_block(ciphertext, tmp,ctx->y);

  memcpy(ctx->y, tmp, BLOCKLEN);
  ctx->mlen+=BLOCKLEN_BITS;

}

/***************************************************************************/
/********************* Encrypt final ***************************************/
/***************************************************************************/

void encrypt_final(struct poet_ctx *ctx, const uint8_t *plaintext,
       uint64_t plen, uint8_t *ciphertext, uint8_t tag[BLOCKLEN])
{
#ifdef DEBUG
  int i;
#endif
  uint64_t offset=0;
  uint64_t len;
  block s;
  block tmp;
  block tmp2;
  while( plen > BLOCKLEN )
    {
      encrypt_block(ctx,  (plaintext+offset), (ciphertext+offset));
      plen   -= BLOCKLEN;
      offset += BLOCKLEN;
    }

  /* Encrypt length of message */
  ctx->mlen+=(plen*8);
  memset(s,0,BLOCKLEN);
  len =  TO_LITTLE_ENDIAN_64(ctx->mlen);
  memcpy(s, &len,8);
  AES_encrypt_wrap(s, s, &(ctx->encdecASM));

  /* Last message block must be padded if necesscary */
  memcpy(tmp,plaintext+offset,plen);
  memcpy(tmp+plen,ctx->tau,BLOCKLEN-plen);


  /* Process last block + tag generation */

  TOP_HASH;
  xor_block(tmp,s,tmp);
  xor_block(ctx->x,tmp,ctx->x);

  AES_encrypt_wrap(ctx->x, tmp, &(ctx->encdecASM));

  BOTTOM_HASH;
  xor_block(tmp2, tmp,ctx->y);
  memcpy(ctx->y, tmp, BLOCKLEN);
  xor_block(tmp,s,tmp2);

  /* Do tag splitting if needed */
  memcpy(ciphertext+offset,tmp,plen);
  memcpy(tag,tmp+plen,BLOCKLEN-plen);


  /* Generate tag */
  TOP_HASH;
  xor_block(ctx->x, ctx->tau, ctx->x);
  xor_block(ctx->x, ctx->tm, ctx->x);

  AES_encrypt_wrap(ctx->x, tmp, &(ctx->encdecASM));


  BOTTOM_HASH;
  xor_block(tmp, ctx->y, tmp);
  xor_block(tmp, ctx->tm, tmp);

  memcpy(tag+(BLOCKLEN-plen),tmp,plen);

}



/***************************************************************************/
/********************* Decrypt block ***************************************/
/***************************************************************************/

void decrypt_block(struct poet_ctx *ctx, const uint8_t ciphertext[16],
       uint8_t plaintext[16])
{
  block tmp;
  BOTTOM_HASH;
  xor_block(ctx->y, ciphertext,ctx->y);

  AES_decrypt_wrap(ctx->y, tmp, &(ctx->encdecASM));

  TOP_HASH;
  xor_block(plaintext, tmp,ctx->x);

  memcpy(ctx->x, tmp, BLOCKLEN);
  ctx->mlen+=BLOCKLEN_BITS;
}


/***************************************************************************/
/********************* Decrypt final ***************************************/
/***************************************************************************/

int decrypt_final(struct poet_ctx *ctx, const uint8_t *ciphertext,
       uint64_t clen, const uint8_t tag[BLOCKLEN],
       uint8_t *plaintext)
{
#ifdef DEBUG
  int i;
#endif
  uint64_t offset=0;
  block s;
  block tmp;
  block tmp2;
  int alpha;
  int beta;
  uint64_t len;

  while( clen > BLOCKLEN )
    {
      decrypt_block(ctx, ciphertext+offset, plaintext+offset);
      clen   -= BLOCKLEN;
      offset += BLOCKLEN;
    }

  /* Encrypt length of message */
  ctx->mlen+=(clen*8);
  memset(s,0,BLOCKLEN);
  len =  TO_LITTLE_ENDIAN_64(ctx->mlen);
  memcpy(s, &len, 8);
  AES_encrypt_wrap(s, s ,&(ctx->encdecASM));


  /* Last ciphertext block must be padded if necesscary */
  memcpy(tmp,ciphertext+offset,clen);
  memcpy(tmp+clen,tag,BLOCKLEN-clen);


  /* Process last block + tag generation */
  BOTTOM_HASH;
  xor_block(tmp,s,tmp);
  xor_block(ctx->y, tmp,ctx->y);

  AES_decrypt_wrap(ctx->y, tmp, &(ctx->encdecASM));

  TOP_HASH;
  xor_block(tmp2, tmp, ctx->x);
  xor_block(tmp2, s, tmp2);
  memcpy(ctx->x,tmp,BLOCKLEN);

  /* Do tag splitting if needed */
  memcpy(plaintext+offset,tmp2,clen);

  alpha = memcmp(tmp2+clen,ctx->tau,BLOCKLEN-clen);

  /* Generate tag */
  TOP_HASH;
  xor_block(ctx->x, ctx->tau ,ctx->x);
  xor_block(ctx->x, ctx->tm ,ctx->x);

  AES_encrypt_wrap(ctx->x, tmp, &(ctx->encdecASM));

  BOTTOM_HASH;
  xor_block(tmp, ctx->y, tmp);
  xor_block(tmp, ctx->tm, tmp);

  beta = memcmp(tmp,tag+(BLOCKLEN-clen),clen);

  return alpha|beta;
}

