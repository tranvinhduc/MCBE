//
// Created by tran on 9/19/18.
//
// Version 0: Very inefficient

#include "esp.h"


element_t esp[MAX_N];

//Elementary Symmetric Polynomial
void computeEsp (int n, element_t *x)
{

    //esp[0] = 1;
    element_init_Zr(esp[0], pairing);
    element_set1(esp[0]);

    for (int i = 1; i <= n ; ++i) {
        element_init_Zr(esp[i], pairing);
        element_set0(esp[i]);
    }
    element_t tmp;
    element_init_Zr(tmp, pairing);

    for (int k = 1; k <= n; k++)
        for(int i = k; i > 0; i--)
        {
            element_mul(tmp, esp[i-1], x[k]);  //esp[i] = esp[i-1] * x[k] + esp[i];
            element_add(esp[i], tmp, esp[i]);

        }
}


//Elementary Symmetric Polynomial
// but in reverse
// that is, esp[user] is coefficient of x^user in P(x) = (x +x1)(x + x2)...(x+xn)
void computeEspInReverse(int n, element_t *x)
{
    computeEsp(n,x);

    //Reverse array
    element_t tmp;
    element_init_Zr(tmp, pairing);

    for (int i = 0; i <= n/2 ; ++i) {
        element_set(tmp, esp[i]);
        element_set(esp[i], esp[n-i]);
        element_set(esp[n-i], tmp);
    }

    element_clear(tmp);

}



/*
element_t P[MAX_N];
*/

/*
// Init  esp
void Init (int n)
{
    for (int i = 0; i <= n ; ++i) {
        element_init_Zr(esp[i], pairing);
        element_set0(esp[i]);
    }
}
*/

/*// P[k] = x1^k + x2^k + ... + xn^k
void computeP(int n, element_t *x)
{
    element_t result;
    element_init_Zr(result, pairing);

    mpz_t tmpk;
    mpz_init(tmpk);

    element_t tmp;
    element_init_Zr(tmp, pairing);

    for (int k = 1; k <= n ; ++k) {
        element_set0 (result);
        for (int i = 1; i <= n; ++i) {
            mpz_set_ui(tmpk, k);
            element_pow_mpz(tmp, x[i], tmpk);
            element_add(result, result, tmp);
        }

        element_set(P[k], result);
    }
    element_clear(result);
}*/
/*//Elementary Symmetric Polynomial
//using Newton's Identity
void computeEsp(int n, element_t *x)
{
    element_t result;
    element_init_Zr(result, pairing);

    element_t tmp;
    element_init_Zr(tmp, pairing);

    element_t tmpk;
    element_init_Zr(tmpk, pairing);

    Init(n);
    computeP(n,x);

    element_set1(esp[0]);  //Init
                            // By Newton'identity,
                           // we can compute e_k based on p_i and e_{k-user}'s

    for (int k = 1; k <= n ; ++k) {
        // k.esp[k] = esp[k-1].P[1] - esp[k-2].P[2] + esp[k-3].p[3] - ... +- e[0]. P[k]

        element_set0 (result);

        for (int i = 1; i <= k; ++i) {
            element_mul(tmp, esp[k - i], P[i]);
            if (i % 2 == 0) {
                element_sub(result, result, tmp);
            }
            else {
                element_add(result, result, tmp);
            }
        }

        element_set0(tmpk);
        element_add_ui(tmpk, tmpk, k);
        element_div(esp[k], result, tmpk);          //esp[k] = result/k;

        //Debug: printf ("%ld\t", esp[k]);
    }

}*/

/*void testMsp ()
{
    element_t x[MAX_SET];
    int n = 1000;

    for(int i = 1 ; i <= n ; i++ ) {
        element_init_Zr(x[i], pairing);
        element_random(x[i]);
    }

//    for (int user = 0; user <= n; ++user) {
//        element_init_Zr(x[user], pairing);
//        element_set1(x[user]);
//    }
//    element_set0(x[4]);

    clock_t begin = clock();

    computeEspInReverse(n, x);

    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf ("%f second\t\n", time_spent);

    *//* for (int k = n; k > 0 ; --k) {
         element_printf ("%B*x^%d + ", esp[k] ,k);
     }
     element_printf ("%B*x^%d\n", esp[0],0);*//*
}*/
