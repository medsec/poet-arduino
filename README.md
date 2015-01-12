poet-arduino
============

Arduino implementation of POET (Pipelineable On-line Encryption with
authentication Tag)

This Project is an Arduino ready adaptation from the POET implementation by Christian Forler.

See the LICENSE file for details of the GPLv3 license in which the POET implementation as well as the AVR-Crypo-Lib used in here are licensed.


Installation
------------

- Download the files in this repository
- Copy the `poet` folder into the Arduino `libraries` folder (same level as your `sketch` folder)
- add `#include <poet.h>` in your sketch.


Usage
-----

At the moment, the POET implementation aes128poet without reduced rounds as well as with reduced(4) rounds are supported. For switching between modes, comment/uncomment the '#define REDUCED_ROUNDS' in poet.h. 

An elaborate usage example can be found in the tests.ino sketch, demonstrating the functions for:

Both Encryption/Decryption
```c
void keysetup(struct poet_ctx *ctx, const uint8_t key[KEYLEN]);
void process_header(struct poet_ctx *ctx, const uint8_t  *header, uint64_t header_len );
```

Encryption
```c
void encrypt_block(struct poet_ctx *ctx, const uint8_t plaintext[16], uint8_t ciphertext[16]);
void encrypt_final(struct poet_ctx *ctx, const uint8_t *plaintext, uint64_t plen, uint8_t *ciphertext, uint8_t tag[BLOCKLEN]);
```

Decryption
```c
void decrypt_block(struct poet_ctx *ctx, const uint8_t ciphertext[16], uint8_t plaintext[16]);
int decrypt_final(struct poet_ctx *ctx, const uint8_t *ciphertext, uint64_t clen, const uint8_t tag[BLOCKLEN], uint8_t *plaintext);
```



Disclaimer
-----------
This software project received funding from the Sillicon Valley
Community Foundation, under the Cisco Systems project Misuse Resistant
Authenticated Encryption for Complex and Low-End Systems (MIRACLE).