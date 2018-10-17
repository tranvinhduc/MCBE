//
// Created by tran on 9/19/18.
//

#ifndef ELEMENTARYSYMMETRICPOLYNOMIAL_ESP_H
#define ELEMENTARYSYMMETRICPOLYNOMIAL_ESP_H

#include <pbc.h>
#include "fix.h"
#include "mcbe.h"

extern element_t esp[MAX_N];
extern element_t P[MAX_N];


void computeEsp(int n, element_t *x);
void computeEspInReverse(int n, element_t *x);


#endif //ELEMENTARYSYMMETRICPOLYNOMIAL_ESP_H
