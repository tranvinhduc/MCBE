//
// Created by tran on 9/22/18.
//

#ifndef MCBEV0_IDIJ_H
#define MCBEV0_IDIJ_H

#include <pbc.h>
#include "fix.h"

typedef struct
{
    int size;
    int elements[MAX_SET];
} Set;

void set_set (Set *b, Set x);
int isSubset(Set s1, Set s2); //test if s1 is a subset of s2
int isElement(Set *S, int x);

void print_set(Set *t);




typedef struct {
    element_t h_alpha[MAX_N + 1];   //index : k
    element_t h_beta[MAX_m];        //index : j
    element_t e[MAX_m];        //index : j
    element_t g_alpha;
} param_t;


typedef struct {
    element_t g[MAX_n][MAX_m];
    element_t h[MAX_N][MAX_m];
    element_t g2;
} secret_key;


typedef struct {
    element_t h;
    element_t g;
    element_t alpha;
    element_t gamma;
    element_t beta[MAX_m];  //index: channel_j
} master_secret_key_t;

typedef struct {
    int i, j;
} pair_t;

//Header
typedef struct{
    element_t C1, C2, C3;
 //   Set channels[MAX_m];
} Header;

/*
typedef struct{
    int user_i, channel_j;
    element_t sk;
} skID;
**/


#endif //MCBEV0_IDIJ_H
