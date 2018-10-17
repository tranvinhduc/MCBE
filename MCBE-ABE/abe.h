//
// Created by tran on 9/22/18.
//

#ifndef MCBEV0_MCBE_H
#define MCBEV0_MCBE_H

#include <pbc.h>
#include "types.h"
#include "fix.h"
#include <pbc_test.h>
#include "esp.h"

extern pairing_t pairing;
extern param_t param;
extern master_secret_key_t msk;


void ABE ();
void Setup();
void Extract(secret_key *sk, master_secret_key_t *msk, param_t *param, Set *Su);
void Encrypt(element_t K, Header *Hdr, param_t *param, Set *B, int t);
int Decrypt_j(int J, element_t Kj, secret_key *sku, Set *Su, param_t *param, Header *Hdr, Set *B, int t);
int Decrypt(element_t K, secret_key *sku, Set *Su, param_t *param, Header *Hdr, Set *B, int t);


#endif //MCBEV0_MCBE_H
