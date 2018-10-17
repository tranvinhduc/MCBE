//
// Created by Tran Vinh Duc on 9/22/18.
//

#include "mcbe.h"

pairing_t pairing;
param_t param;
master_secret_key_t msk;

//Read pairing from files
void MCBE()
{
    char input[1024];
    size_t count = fread(input, 1, 1024, stdin);
    if (!count) pbc_die("input error");
    pairing_init_set_buf(pairing, input, count);
}


/*
 * Parameters are very large. It takes long time to finish!
 * */
void Setup()
{

    // Master secret key
    element_init_G1(msk.g, pairing);
    element_random(msk.g);

    element_init_G2(msk.h, pairing);
    element_random(msk.h);

    element_init_Zr(msk.alpha, pairing);
    element_random(msk.alpha);

    for (int j = 0; j < MAX_m; ++j) {
        element_init_Zr(msk.beta[j], pairing);
        element_random(msk.beta[j]);
    }

    // Param
    // h^(\alpha^k)
    element_init_G2(param.h_alpha[0], pairing);
    element_set(param.h_alpha[0], msk.h);
    for (int k = 1; k < MAX_N; ++k) {
        element_init_G2(param.h_alpha[k], pairing);
        element_pow_zn(param.h_alpha[k], param.h_alpha[k-1], msk.alpha);
    }

    //h^(\beta.\alpha) Take long time to finish!!!
    for (int j = 0; j < MAX_m; ++j) {
        for (int k = 0; k < MAX_N; ++k) {
            element_init_G2(param.h_beta_alpha[j][k], pairing);
            element_pow_zn(param.h_beta_alpha[j][k], param.h_alpha[k], msk.beta[j]);
        }
    }

    // e(g,h)^beta_j
    element_t e;
    element_init_GT(e, pairing);
    pairing_apply(e, msk.g, msk.h, pairing);

    for (int j = 0; j < MAX_m; ++j) {
        element_init_GT(param.e_beta[j], pairing);
        element_pow_zn(param.e_beta[j], e, msk.beta[j]);
    }

    element_init_G1(param.g_alpha, pairing);
    element_pow_zn(param.g_alpha, msk.g, msk.alpha);
}

void Extract(skID *skIDij, ID ij)
{
    element_t hash_IDij;
    hashID(hash_IDij, ij);

    element_t tmp;
    element_init_Zr(tmp, pairing);
    element_add(tmp, msk.alpha, hash_IDij);
    element_div(tmp, msk.beta[ij.channelj], tmp);

    element_init_G1(skIDij->sk, pairing);
    element_pow_zn(skIDij->sk, msk.g, tmp);

    skIDij->user_i=ij.useri;
    skIDij->channel_j=ij.channelj;

    element_clear(tmp);
    element_clear(hash_IDij);
}

void Encrypt (element_t *Keys, Header *Hdr, param_t *param, Set *channels, int t)
{
    element_t hashS[MAX_N];
    int n = 0;

    for (int j = 0; j < t; ++j) {
        for (int i = 0; i < channels[j].size; ++i) {
            ID ij = {channels[j].elements[i],j};
            hashID(hashS[++n], ij);
            //Debug:
            // printf("%d,%d\n", ij.user_i, ij.channel_j);
        }
    }

    // K <- random
    element_t K;
    element_init_Zr(K, pairing);
    element_random(K);

    // Keys = [K0, K1, ..., K[t-1]
    for (int j = 0; j < t; ++j) {
        element_init_GT(Keys[j],pairing);
        element_pow_zn(Keys[j], param->e_beta[j], K);
    }

    //C1 = g^-alpha k = (g^alpha)^{-k}
    element_t K_;
    element_init_Zr(K_, pairing);
    element_neg(K_, K);

    element_init_G1(Hdr->C1, pairing);
    element_pow_zn(Hdr->C1, param->g_alpha, K_);

//  DEBUG  double time1 = pbc_get_time();

    //C2 = (h^\alph^0)^esp[0] . (h^\alph^1)^esp[1]. ... . (h^\alph^n)^esp[n]
    computeEspInReverse(n, hashS);

//    DEBUG double time2 = pbc_get_time();
//    DEBUG printf ("Time for ESP: %fms\n", (time2 - time1)*1000.0);

    element_t tmp;
    element_init_G2(tmp, pairing);

    element_t result;
    element_init_G2(result, pairing);
    element_set1(result);

  /*  DEBUG double time1, time2;
    DEBUG time1 = pbc_get_time();
*/
    // Very slow *******************
    for (int k = 0; k <= n ; ++k) {
        element_pow_zn(tmp, param->h_alpha[k], esp[k]);
        element_mul(result, result, tmp);
    }
   /* DEBUG time2 = pbc_get_time();
      DEBUG printf ("Time for result: %fms\n", (time2 - time1)*1000.0);
    */

//    DEBUG time1 = pbc_get_time();

    element_init_G2(Hdr->C2, pairing);
    element_pow_zn(Hdr->C2, result, K);

//    DEBUG time2 = pbc_get_time();
//    DEBUG printf ("Time for pairing: %fms\n", (time2 - time1)*1000.0);


    for (int k = 1; k <= n; ++k) {
        element_clear(hashS[k]);
    }


    element_clear(K);
    element_clear(K_);
    element_clear(tmp);
    element_clear(result);
}

int Decrypt(element_t Kj, skID skIDij, param_t *param, Header *Hdr, Set *channels, int t)
{
    //Check if user_i in channels[channel_j]
    int found = 0;
    for (int i = 0; i < channels[skIDij.channel_j].size; ++i) {
        if (skIDij.user_i == channels[skIDij.channel_j].elements[i]) {
            found = 1;
            break;
        }
    }
    if (found == 0) return 1;

    /*
     * 1. compute Elementary Symmetric Polynomial esp[k]
     *
     * */
    element_t hashS[MAX_N];
    int n = 0;

    for (int j = 0; j < t; ++j) {
        for (int i = 0; i < channels[j].size; ++i) {
            if (skIDij.channel_j != j || skIDij.user_i != channels[j].elements[i]){
                ID ij = {channels[j].elements[i],j};
                hashID(hashS[++n], ij);
            }
        }
    }

    computeEspInReverse(n, hashS);

    /*
     *
     * 2. Compute h^\gamma = [ product h^(\beta_j\alpha^k/\alpha)^ esp[k]    for k = 1 ... n ]
     *
     * */
    element_t tmp;
    element_init_G2(tmp, pairing);

    element_t K_;
    element_init_G2(K_, pairing);
    element_set1(K_);

/*
    DEBUG double time1 = pbc_get_time();
*/
    // Very slow ***************
    for (int k = 1; k <= n ; ++k) {
        element_pow_zn(tmp, param->h_beta_alpha[skIDij.channel_j][k-1], esp[k]);
        element_mul(K_, K_, tmp);
    }
/*
    DEBUG double time2 = pbc_get_time();
    DEBUG printf ("Time for result: %fms\n", (time2 - time1)*1000.0);
*/

    /*
     * 3. Compute Kj
     *
     *
     * */
    element_t B;
    element_init_Zr(B, pairing);
    element_set(B, esp[0]);

    /*
     * 3.1. compute B_inv = 1/B
     *
     * */
    element_t B_inv;
    element_init_Zr(B_inv, pairing);
    element_invert(B_inv, B);

    /*
     * 3.2. Compute e(C1,K_)
     * */
    element_t result1;
    element_init_GT(result1, pairing);
    pairing_apply(result1, Hdr->C1, K_, pairing);


    /*3.3. Compute e(sk, C2)
     * */
    element_t result2;
    element_init_GT(result2, pairing);
    pairing_apply(result2, skIDij.sk, Hdr->C2, pairing);


    element_init_GT(Kj, pairing);
    element_mul(Kj, result1, result2);


    element_pow_zn(Kj, Kj, B_inv);

    for (int k = 1; k <= n; ++k) {
        element_clear(hashS[k]);
    }

    return 0;

}

