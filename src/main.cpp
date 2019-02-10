/*
 * main.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 9th February 2019.
 *
 *
*/

/* Landmine main; woot! */

#include <cstdio>
#include <algorithm>
#include <cstdlib>
#include <csignal>
#include <unistd.h>

#include "landmine.h"

/* main does not accept argc and argv */
int main(void) {
    Landmine landmine(80);
    landmine.start();

    return 0;
}
