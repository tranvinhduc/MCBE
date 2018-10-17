//
// Created by tran on 9/22/18.
//

#include <pbc.h>
#include "types.h"
#include "mcbe.h"

/*
 * Data type: Set
 * /
 */
void set_set (Set *b, Set x)
{
    b->size = x.size;
    for(int i = 0; i < b->size; i++)
        b->elements[i] = x.elements[i];
}

void print_set(Set *t)
{
    printf("%5d:[ ", t->size );
    for(int i = 0; i < t->size; i++)
        printf("%d, ", t->elements[i]);
    printf("]\n");
}


int isSubset(Set s1, Set s2) //s1 is a subset of s2
{
    if (s1.size > s2.size)
        return 0;

    int j= 0;
    for (int i = 0; i < s1.size; i++)
    {
        j = 0;
        for (; j < s2.size; j++)
            if (s1.elements[i] == s2.elements[j]) break;

        if (j == s2.size) return 0;

    }

    return 1;
}

/*
 * Data type: ID  (restricted to ij, TODO: add char * id;
 */

int sizeOf(ID ij)
{
    return (int)(2*sizeof(int));
}

void hashID(element_t hash, ID IDij)
{
    element_init_Zr(hash, pairing);
    element_from_hash(hash, &IDij, sizeOf(IDij));
}

