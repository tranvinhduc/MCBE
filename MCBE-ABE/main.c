
#include "abe.h"
#include "readfile.h"

#define NUMTEST 100


int main(int argc, char const * argv[]) {

    if (argc < 1)
    {
        perror("Usage: MCBE datafile");
        exit(-1);
    }
/*
    Set B[MAX_m] = {
            {2,{1,2}},
            {3,{3,4,5}},
            {4,{6,7,8,6}}
    };

    int t = 3;     // Number of B

    Set Su = {3, {1,3,8}};
*/

    Set B[MAX_m];
    int t;


    Set Su;
    Su.size = MAX_n;
    for (int i = 0; i < Su.size; ++i) {
        Su.elements[i] = i;
    }



    ABE();

    double time1, time2;

    time1 = pbc_get_time();

    Setup();

    time2 = pbc_get_time();

    printf ("Setup (): %fs\n", (time2 - time1)*1000.0 / NUMTEST);

    secret_key sk;


    double everage = 0; 
    /* for (int l = 0; l < NUMTEST; ++l) { */


        time1 = pbc_get_time();

        Extract(&sk, &msk, &param, &Su);

        time2 = pbc_get_time();
        everage += (time2 - time1);
    /* } */
    printf ("Extract (): %fms\n", everage*1000.0);


    char *file[9] = {"datatest/102.txt", "datatest/104.txt", "datatest/108.txt",\
                    "datatest/202.txt", "datatest/204.txt", "datatest/208.txt",\
                    "datatest/252.txt", "datatest/254.txt", "datatest/258.txt"};

    printf ("File & Encode & Decode \\\\ \n");
    for (int i = 0; i < 9 ; ++i) {

        readFiles(file[i], B, &t, &Su);
        printf("%s & \t", file[i]);

        element_t K;
        Header Hdr;

        everage = 0;
        for (int l = 0; l < NUMTEST; ++l) {


            time1 = pbc_get_time();

            Encrypt(K, &Hdr, &param, B, t);

            time2 = pbc_get_time();
            everage += (time2 - time1);
        }

        printf("%fms & \t", everage * 1000.0 / NUMTEST);


        element_t Kj;

        int fail;
        everage = 0;
        for (int l = 0; l < NUMTEST; ++l) {
            time1 = pbc_get_time();
            fail =
                    Decrypt(Kj, &sk, &Su, &param, &Hdr, B, t);
            time2 = pbc_get_time();
            everage += (time2 - time1);

        }
        printf("%fms &\t \n", everage * 1000.0 / NUMTEST);
/*

        if (fail) {
            printf("Cannot decrypt Hdr!\n");
            return 0;
        }

        if (!element_cmp(K, Kj))
            printf("Successful!\n");
        else printf("Fail!\n");

        element_printf("K=%B\n", K);
        element_printf("Kj = %B\n", Kj);
        */
    }
    return 0;
}
