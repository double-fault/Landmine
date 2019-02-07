#include <string>
#include <iostream>
#include <stdio.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include <regex>

#include <faup/faup.h>
#include <faup/decode.h>
#include <faup/options.h>
#include <faup/output.h>

#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

int main(void) {
    boost::regex r("(?is)^[0-9a-z]{20,}\s*$");
    std::string s = "blahblahblahaaaaaaaaaaaaaa";

    fmt::print("{}\n", boost::regex_match(s, r));

    return 0;
}
