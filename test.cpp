#include <boost/regex.hpp>
#include <boost/xpressive/xpressive.hpp>

#include <fmt/format.h>
#include <fmt/printf.h>
#include <fmt/core.h>

#include <string>
#include <vector>

#include <stdio.h>

using namespace boost::xpressive;

std::string join(std::vector<std::string> elements, char del) {
    std::string ret;
    for (auto &s:elements) ret += (s + del);
    ret.pop_back(); return ret;
}

int main(void) {
    std::vector<std::string> patterns = {
        "[^\"]*-reviews?(?:-(?:canada|(?:and|or)-scam))?/?",
        "[^\"]*-support/?"
    };

    std::string s_r = fmt::sprintf("(^[^\n ]*$<a href=\"(?:%s)\"^[^\n ]*$)|(^[^\n ]*$<a href=\"[^\"]*\"(?:\\s+\"[^\"]*\")*>(?:%s)</a>)",
            join(patterns, '|'), join(patterns, '|'));

    //std::string s = "<a href=\"http://aaaahvfvyrg///\" rel=\"aaa\"bbb";
    std::string s = "<p><a href=\"http://www.supplementhealthexpert.com/keto-rapid-diet-reviews/\" rel=\"nofollow noreferrer\">http://www.supplementhealthexpert.com/keto-rapid-diet-reviews/</a></p>";

    boost::regex b_re(s_r);
    boost::smatch b_what;
    if (boost::regex_match(s, b_what, b_re)) {
        puts("Boost.Regex match");
        fmt::print("{}\n", b_what[0]);
    } else
        puts("nah");

    sregex x_re = sregex::compile(s_r);
    smatch x_what;

    if (regex_match(s, x_what, x_re))
    {
        puts("Boost.Xpressive match");
        fmt::print("{}\n", x_what[0]);
    } else
        puts("nah");

    return 0;
}

