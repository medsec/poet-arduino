#include <poet.h>

void setup() {
  Serial.begin(9600);
  pinMode(13, OUTPUT);
  
  tests();
}

void loop() {  
  //blinking for signalling being alive
  digitalWrite(13, HIGH);   // turn the LED on (HIGH is the voltage level)
  delay(1000);              // wait for a second
  digitalWrite(13, LOW);    // turn the LED off by making the voltage LOW
  delay(1000);              // wait for a second
}


void tests()
{
  Serial.println(F("Test started"));

  int result=0;

  result |= test1();
  result |= test2();
  result |= test3();
  result |= test4();
  
  Serial.println(F("Test finished"));

  if (result) Serial.println(F("Test result:  FAILED"));
  else        Serial.println(F("Test result:  SUCCESS"));
}

/******************************************************************************/

/* No header + 1 block message */
int test1()
{
  poet_ctx ctx;
  uint8_t k[BLOCKLEN] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  uint8_t m[BLOCKLEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  uint8_t c[BLOCKLEN];
  uint8_t t[BLOCKLEN];

  keysetup(&ctx,k);

  process_header(&ctx, NULL,0);
 
  encrypt_final(&ctx,m,BLOCKLEN, c, t);

  /*test_output(&ctx, k, BLOCKLEN, NULL, 0, m, BLOCKLEN, c, BLOCKLEN,
	      t, BLOCKLEN);*/

  keysetup(&ctx,k);
  process_header(&ctx, NULL,0);
  return decrypt_final(&ctx,c, BLOCKLEN, t, m);
}

/******************************************************************************/

/* 1 block header + 3.5 block message */
int test2()
{
  poet_ctx ctx;
  uint8_t k[BLOCKLEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  uint8_t h[BLOCKLEN] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};


  uint8_t m[3*BLOCKLEN+8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			      0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe};

  uint8_t c[3*BLOCKLEN+8];
  uint8_t t[BLOCKLEN];

  keysetup(&ctx,k);
  process_header(&ctx, h ,BLOCKLEN);
  encrypt_final(&ctx,m,3*BLOCKLEN+8, c, t);
  /*test_output(&ctx, k, BLOCKLEN, h, BLOCKLEN, m, 3*BLOCKLEN+8, c,
	      3*BLOCKLEN+8, t, BLOCKLEN); */

  keysetup(&ctx,k);
  process_header(&ctx, h, BLOCKLEN);
  return decrypt_final(&ctx, c, 3*BLOCKLEN+8, t, m);
}

/*******************************************************************/

/* 1.5 header + no message */
int test3()
{
  struct poet_ctx ctx;
  uint8_t k[BLOCKLEN] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  uint8_t h[BLOCKLEN+8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			    0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe};

  uint8_t t[BLOCKLEN];

  keysetup(&ctx,k);
  process_header(&ctx, h ,BLOCKLEN+8);
  encrypt_final(&ctx, NULL, 0, NULL, t);

  /*test_output(&ctx, k, BLOCKLEN, h, BLOCKLEN+8, NULL, 0, NULL, 0, t, BLOCKLEN);*/

  keysetup(&ctx,k);
  process_header(&ctx, h, BLOCKLEN+8);
  return decrypt_final(&ctx, NULL, 0, t, NULL);
}

/*******************************************************************/

/* 1.5 header + 3.25 message */
int test4()
{
  struct poet_ctx ctx;
  uint8_t k[BLOCKLEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

  uint8_t h[BLOCKLEN+8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			    0xde, 0xad, 0xbe, 0xef, 0xde, 0xaf, 0xba, 0xbe};

  uint8_t m[3*BLOCKLEN+4] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			      0xfe, 0xfe, 0xba, 0xbe};

  uint8_t c[3*BLOCKLEN+4];
  uint8_t t[BLOCKLEN];

  keysetup(&ctx,k);
  process_header(&ctx, h ,BLOCKLEN+8);
  encrypt_final(&ctx, m, 3*BLOCKLEN+4, c, t);

  keysetup(&ctx,k);
  process_header(&ctx, h, BLOCKLEN+8);
  
  /*test_output(&ctx, k, BLOCKLEN, h, BLOCKLEN+8, m, 3*BLOCKLEN+4,
	      c, 3*BLOCKLEN+4, t, BLOCKLEN);*/
  
  return decrypt_final(&ctx, c,  3*BLOCKLEN+4, t, m);
}




void printRoundkey(aes128_ctx_t ctx)
{
  Serial.println(F("Roundkey: "));
  for(int i = 0; i!=10;i++)
  {
    for(int j=0; j< 16;j++)
  {
    Serial.print(ctx.key[i].ks[j], HEX);
  }
  Serial.println(" ");
  }
}

void test_output(const struct poet_ctx *ctx,
		 const uint8_t *key, const uint32_t klen,
		 const uint8_t *ad,  const uint32_t hlen,
		 const uint8_t *m,   const uint32_t mlen,
		 const uint8_t *c,   const uint32_t clen,
		 const uint8_t *t,   const uint32_t tlen)

{
  Serial.println(F("SK: "));
  printArray(key);
  
  print_context(ctx);
  
  Serial.println(F("Header/Nonce: "));
  printArray(ad);
  
  Serial.println(F("Plaintext: "));
  printArray(m);
  
  Serial.println(F("Ciphertext: "));
  printArray(c);
  
  Serial.println(F("Tag: "));
  printArray(t);
  
  Serial.println(F(" "));
  Serial.println(F(" "));
}

void print_context (const struct poet_ctx *ctx)
{
  Serial.println(F("K: "));
  printArray(ctx->k);
  
  Serial.println(F("L: "));
  printArray(ctx->l);
  
  Serial.println(F("LT: "));
  printArray(ctx->lt);
  
  Serial.println(F("LB: "));
  printArray(ctx->lb);
  
  Serial.println(F("TM: "));
  printArray(ctx->tm);
  
  Serial.println(F("Tau: "));
  printArray(ctx->tau);
  
  Serial.println(F("X: "));
  printArray(ctx->x);
  
  printRoundkey(ctx->aes_ltASM);
}

void printArray(const byte* array)
{
  for(int i=0; i< 16;i++)
  {
    Serial.print(array[i], HEX);
  }
  Serial.println(" ");
}


void aesTest()
{
  uint8_t key[] = 
  {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
  } ;
  uint8_t data[] =
  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  
  int microsOld = micros();
  aes128_enc_single(key, data);
  int microsNew = micros();
  
  Serial.print(F("Microseconds: "));
  Serial.println(microsNew-microsOld);

  
  
  Serial.print(F("encrypted:"));
  for(int i=0; i< 16;i++)
  {
    Serial.print(data[i], HEX);
  }
  Serial.println(" ");
  Serial.println(" ");
  
  
}



