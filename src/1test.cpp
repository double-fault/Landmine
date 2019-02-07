#include <stdio.h>
#include <algorithm>
#include <functional>
#include <set>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

void foo(std::set<std::string> a) {
    for (const std::string &s:a) 
        fmt::print("{}\n", s);
}

int main(void) {
    foo({});
    return 0;
}

