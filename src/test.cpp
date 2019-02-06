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
    boost::xpressive::sregex r = boost::xpressive::sregex::compile("\b(?P<words>(?P<word>[a-z]+))(?:[][\\s.,;!/\()+_-]+(?P<words>(?P=word))){4,}\b");
    std::string s("blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah");

    fmt::print("{}\n", boost::xpressive::regex_match(s, r));

    return 0;
}
