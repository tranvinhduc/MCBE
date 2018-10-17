//
// Created by tran on 9/26/18.
//

#include "readfile.h"

void readFiles(const char *filename, Set *channels, int *t)
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
        fscanf(fp, "%d", &channels[j].size);
        for (int i = 0; i < channels[j].size; ++i) {
            fscanf(fp, "%d", &channels[j].elements[i]);
        }
    }

    fclose(fp);

}