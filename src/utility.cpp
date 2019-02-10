/*
 * utility.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 10th February 2019/
 *
 *
*/

#include <string>
#include <vector>

#include "utility.h"

std::string join(std::vector<std::string> elements, char del) {
    std::string ret;
    for (auto &s:elements) ret += (s + del);
    ret.pop_back(); return ret;
}

