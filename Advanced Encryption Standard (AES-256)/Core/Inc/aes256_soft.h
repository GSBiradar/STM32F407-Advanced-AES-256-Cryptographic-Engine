/*
 * aes256_soft.h
 *
 *  Created on: Feb 23, 2026
 *      Author: Guru SB
 */

//#ifndef INC_AES256_SOFT_H_
//#define INC_AES256_SOFT_H_

#ifndef AES256_SOFT_H
#define AES256_SOFT_H

#include <stdint.h>

typedef struct {
    uint32_t round_key[60];  // 15 rounds * 4 = 60 words
    int rounds;
} AES256_CTX;

void AES256_KeyExpansion(AES256_CTX *ctx, const uint8_t *key);
void AES256_CBC_Encrypt(AES256_CTX *ctx, uint8_t *output,
                        const uint8_t *input, uint32_t length,
                        const uint8_t *iv);
void AES256_CBC_Decrypt(AES256_CTX *ctx, uint8_t *output,
                        const uint8_t *input, uint32_t length,
                        const uint8_t *iv);



#endif /* INC_AES256_SOFT_H_ */
