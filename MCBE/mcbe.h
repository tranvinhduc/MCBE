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

void MCBE ();
void Setup();
void Extract(skID *skIDij, ID ij);
void Encrypt (element_t *Keys, Header *Hdr, param_t *param, Set *channels, int t);
int Decrypt(element_t Kj, skID skIDij, param_t *param, Header *Hdr, Set *channels, int t);

#endif //MCBEV0_MCBE_H
