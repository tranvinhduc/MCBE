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
void print_set(Set *t);

typedef struct
{
    int useri,channelj;  // User user_i  subscribe to chanel channel_j
} ID;
void hashID(element_t hash, ID IDij);
int sizeOf(ID ij);


typedef struct {
    element_t h_alpha[MAX_N];   //index : k
    element_t h_beta_alpha[MAX_m][MAX_N]; //index : jk
    element_t e_beta[MAX_m]; //index : channel_j
    element_t g_alpha;
} param_t;

typedef struct {
    element_t h;
    element_t g;
    element_t alpha;
    element_t beta[MAX_m];  //index: channel_j
} master_secret_key_t;



//Header
typedef struct{
    element_t C1, C2;
 //   Set channels[MAX_m];
} Header;

typedef struct{
    int user_i, channel_j;
    element_t sk;
} skID;

#endif //MCBEV0_IDIJ_H
