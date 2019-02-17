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
#include <signal.h>
#include <unistd.h>
#include <execinfo.h>

#define BOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED
#include <boost/stacktrace.hpp>

#include <fmt/format.h>
#include <fmt/printf.h>
#include <fmt/core.h>

#include "landmine.h"

/* signal handler from https://stackoverflow.com/a/77336/4688119 */
/* slightly modified */
void handler(int sig) {
    void *array[10];
    size_t size;

    /* get void*'s for all entries on the stack */
    size = backtrace(array, 10);

    /* print out all the frames to stderr */
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}


/* main does not accept argc and argv */
int main(void) {
    signal(SIGABRT, handler); /* install our handler */

    Landmine landmine(80);
    landmine.init();
    landmine.start();

    return 0;
}
