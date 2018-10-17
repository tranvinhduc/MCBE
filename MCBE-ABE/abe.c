//
// Created by Tran Vinh Duc on 9/22/18.
//

#include "abe.h"

pairing_t pairing;
param_t param;
element_t Attributes[MAX_n][MAX_m];

master_secret_key_t msk;

//Read pairing from files
void ABE()
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

    for (int i = 0; i < MAX_n ; ++i) {
        for (int j = 0; j < MAX_m; ++j) {
            element_init_Zr(Attributes[i][j], pairing);
            element_random(Attributes[i][j]);
        }
    }


    element_init_G2(msk.h, pairing);
    element_random(msk.h);
    element_init_G1(msk.g, pairing);
    element_random(msk.g);


    element_init_Zr(msk.alpha,pairing);
    element_random(msk.alpha);
    element_init_Zr(msk.gamma,pairing);
    element_random(msk.gamma);

    for (int j = 0; j < MAX_m; ++j) {
        element_init_Zr(msk.beta[j], pairing);
        element_random(msk.beta[j]);
    }


    element_init_G2(param.h_alpha[0], pairing);
    element_set(param.h_alpha[0], msk.h);

    for (int k = 1; k < MAX_N; ++k) {
        element_init_G2(param.h_alpha[k], pairing);
        element_pow_zn(param.h_alpha[k], param.h_alpha[k-1], msk.alpha);
    }

    element_t p;
    element_init_GT(p, pairing);
    pairing_apply(p, msk.g, msk.h, pairing);
    element_pow_zn(p, p, msk.gamma);        // p = e(g,h)^\gamma


    for (int j = 0; j < MAX_m; ++j) {
        element_init_G2(param.h_beta[j], pairing);
        element_pow_zn(param.h_beta[j], msk.h, msk.beta[j]);

        element_init_GT(param.e[j], pairing);
        element_pow_zn(param.e[j], p, msk.beta[j]);
    }

    element_init_G1(param.g_alpha, pairing);
    element_pow_zn(param.g_alpha, msk.g, msk.alpha);
}

void Extract(secret_key *sk, master_secret_key_t *msk, param_t *param, Set *Su)
{
    element_t su;
    element_init_Zr(su,pairing);
    element_random(su);

    element_t tmp, tmp1, tmp2;
    element_init_Zr(tmp, pairing);
    element_init_Zr(tmp1, pairing);
    element_init_Zr(tmp2, pairing);

    for (int j = 0; j < MAX_m; ++j) {
        element_mul(tmp1, msk->beta[j], su);
        for (int i = 0; i < Su->size; ++i) {
            element_add(tmp2, msk->alpha, Attributes[Su->elements[i]][j]);
            element_div(tmp, tmp1, tmp2);
            element_init_G1(sk->g[Su->elements[i]][j], pairing);
            element_pow_zn(sk->g[Su->elements[i]][j], msk->g, tmp);
        }
    }


    for (int j = 0; j < MAX_m; ++j) {
        element_mul(tmp, msk->beta[j], su);
        for (int k = 0; k < MAX_N; ++k) {
            element_init_G2(sk->h[k][j],pairing);
            element_pow_zn(sk->h[k][j], param->h_alpha[k], tmp);
        }
    }


    element_add(tmp, su, msk->gamma);
    element_init_G1(sk->g2, pairing);
    element_pow_zn(sk->g2, msk->g, tmp);
}


void Encrypt(element_t K, Header *Hdr, param_t *param, Set *B, int t)
{
    

    // r <- random
    element_t r;
    element_init_Zr(r, pairing);
    element_random(r);

    // K = 
    element_init_GT(K, pairing);
    element_set1(K);

    for (int j = 0; j < t; ++j) {
        element_mul(K, K, param->e[j]);
    }
    element_pow_zn(K, K, r);


    //C1 = g^{-alpha r} = (g^alpha)^{-r}
    element_t r_;               // r_ = -r
    element_init_Zr(r_, pairing);
    element_neg(r_, r);

    element_init_G1(Hdr->C1, pairing);
    element_pow_zn(Hdr->C1, param->g_alpha, r_);


    // C2 =
    element_init_G2(Hdr->C2, pairing);
    element_set1(Hdr->C2);

    for (int j = 0; j < t; ++j) {
        element_mul(Hdr->C2, Hdr->C2, param->h_beta[j]);
    }
    element_pow_zn (Hdr->C2, Hdr->C2, r);

    
    //C3 =
    element_t S[MAX_N];
    int n = 0;

    for (int j = 0; j < t; ++j) {
        for (int i = 0; i < B[j].size; ++i) {
            n++;
            element_init_Zr(S[n], pairing);
            element_set(S[n], Attributes[B[j].elements[i]][j]);
        }
    }
    
    computeEspInReverse(n, S);

    element_t tmp;
    element_init_G2(tmp, pairing);

    element_t result;
    element_init_G2(result, pairing);
    element_set1(result);


    // Very slow *******************
    for (int k = 0; k <= n ; ++k) {
        element_pow_zn(tmp, param->h_alpha[k], esp[k]);
        element_mul(result, result, tmp);
    }

    element_init_G2(Hdr->C3, pairing);
    element_pow_zn(Hdr->C3, result, r);


    for (int k = 1; k <= n; ++k) {
        element_clear(S[k]);
    }


    element_clear(r);
    element_clear(r_);
    element_clear(tmp);
    element_clear(result);
}

int Decrypt_j(int J, element_t Kj, secret_key *sku, Set *Su, param_t *param, Header *Hdr, Set *B, int t)
{
    //Check if I in (B_J \cap Su)
    int found = 0;
    int I = -1;
    for (int l = 0; l < Su->size; ++l) {
        if (isElement(&B[J], Su->elements[l]) != -1)
        {
            found = 1;
            I = Su->elements[l];
            break;
        }
    }

    if (!found) return -1;


    /*
     * 1. compute Elementary Symmetric Polynomial esp[k]
     *
     * */
    element_t S[MAX_N];
    int n = 0;

    for (int j = 0; j < t; ++j) {
        for (int i = 0; i < B[j].size; ++i) {
            if (j != J || I != B[j].elements[i]){
                n++;
                element_init_Zr(S[n], pairing);
                element_set (S[n], Attributes[B[j].elements[i]][j]);
            }
        }
    }


    computeEspInReverse(n, S);

    /*
     *
     * 2. Compute h^\theta = [ product h^(\alpha^k/\alpha\beta su)^ esp[k]    for k = 1 ... n ]
     *
     * */
    element_t tmp;
    element_init_G2(tmp, pairing);

    element_t Kprime;
    element_init_G2(Kprime, pairing);
    element_set1(Kprime);


    // Very slow ***************
    for (int k = 1; k <= n ; ++k) {
        element_pow_zn(tmp, sku->h[k-1][J], esp[k]);
        element_mul(Kprime, Kprime, tmp);
    }

    /*
     * 3. Compute Kj
     *
     *
     * */
    element_t D;
    element_init_Zr(D, pairing);
    element_set(D, esp[0]);

    /*
     * 3.1. compute D_inv = 1/D
     *
     * */
    element_t D_inv;
    element_init_Zr(D_inv, pairing);
    element_invert(D_inv, D);


    /*
     * 3.2. Compute e(C1,Kprime)
     * */
    element_t result1;
    element_init_GT(result1, pairing);
    pairing_apply(result1, Hdr->C1, Kprime, pairing);

    /*3.3. Compute e(sk, C2)
     * */
    element_t result2;
    element_init_GT(result2, pairing);
    pairing_apply(result2, sku->g[I][J], Hdr->C3, pairing);//


    element_init_GT(Kj, pairing);
    element_mul(Kj, result1, result2);


    element_pow_zn(Kj, Kj, D_inv);

    for (int k = 1; k <= n; ++k) {
        element_clear(S[k]);
    }

    return 0;

}

int Decrypt(element_t K, secret_key *sku, Set *Su, param_t *param, Header *Hdr, Set *B, int t)
{
    element_t Kprime, Ktmp;
    element_init_GT(Kprime, pairing);
    element_set1(Kprime);


    for (int j = 0; j < t; ++j) {
        if (Decrypt_j(j, Ktmp, sku, Su, param, Hdr, B, t)) return -1;
        element_mul(Kprime, Kprime, Ktmp);
        element_clear(Ktmp);
    }

    element_invert(Kprime, Kprime);

    element_init_GT(Ktmp, pairing);
    pairing_apply(Ktmp, sku->g2, Hdr->C2, pairing);

    element_init_GT(K, pairing);
    element_mul(K, Ktmp, Kprime);

    return 0;
}
