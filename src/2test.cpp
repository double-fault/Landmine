#include <functional>
#include <stdio.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

int foo(int a) {
    fmt::print("{}\n", a);
    return a;
}

void bar(int a, std::function<int(int)> baz) {
    fmt::print("yay {}\n", baz(a));
}

int main(void) {
    bar(999, &foo);
    return 0;
}

