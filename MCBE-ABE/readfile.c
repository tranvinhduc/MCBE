//
// Created by tran on 9/26/18.
//

#include "readfile.h"

void readFiles(const char *filename, Set *B, int *t, Set *Su)
{
    FILE * fp;

    fp = fopen (filename, "r+");
    if (fp == 0)
    {
        perror("Cannot open files!\n");
        exit (-1);
    }

    fscanf(fp, "%d", t);

    for (int j = 0; j < *t; ++j) {
        fscanf(fp, "%d", &B[j].size);
        for (int i = 0; i < B[j].size; ++i) {
            fscanf(fp, "%d", &B[j].elements[i]);
        }
    }

  //  fscanf(fp, "%d", &Su->size);

    //for (int j = 0; j < Su->size; ++j) {
    //    fscanf(fp, "%d", &Su->elements[j]);
    //}

    fclose(fp);

}