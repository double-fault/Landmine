/*
 * lists.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 *
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include <boost/regex.hpp>

#include "json.hpp"
#include "findspam.h"
#include "post.h"
#include "lists.h"

List::List() {}

void List::init(json o) {
    int flag = 0;
    for (auto& ele: o.items()) {
        flag = 1;
        elements.push_back(ele.value());
        consolidated += ele.value();
        consolidated += "|";
    }
    if (flag) consolidated.pop_back();
}

List::get_consolidated_string(void) { return consolidated; }

Lists::Lists(std::string file) {
    data_file = file;
    std::ifstram i(data_file);
    json j;
    i >> j;

    bad_keywords.init(j["bad_keywords"]);
    bad_keywords_nwb.init(j["bad_keywords_nwb"]);
    watched_keywords.init(j["watched_keywords"]);
    blacklisted_websites.init(j["blacklisted_websites"]);
    blacklisted_usernames.init(j["blacklisted_usernames"]);
    blacklisted_numbers.init(j["blacklisted_numbers"]);
    watched_numbers.init(j["watched_numbers"]);

    std::string temp = "(?is)(?:^|\b|(?w:\b))(?:%s)(?:\b|(?w:\b)|$)|%s";
    r_bad_keywords = (fmt::sprintf(temp, bad_keywords.get_consolidated_string,
                bad_keyword_nwb.get_consolidated_string));

    temp = "(?is)(?:^|\b|(?w:\b))(?:%s)(?:\b|(?w:\b)|$)";
    r_watched_keywords = (fmt::sprintf(temp, watched_keywords.get_consolidated_string));

    temp = "(?i)(%s)";
    r_blacklisted_websites = (fmt::sprintf(temp, blacklisted_websites.get_consolidated_string));

    temp = "(?i)(%s)";
    r_blacklisted_usernames = (fmt::sprintf(temp, blacklisted_usernames.get_consolidated_string));

    boost::regex e ("\D");
    for (auto &num: blacklisted_numbers.elements) {
        bad_numbers_normalized.first.insert(num);
        bad_numbers_normalized.second.insert(boost::regex_replace(num, e, ""));
    }
    for (auto &num: watched_numbers.elements) {
        watched_numbers_normalized.first.insert(num);
        watched_numbers_normalized.second.insert(boost::regex_replace(num, e, ""));
    }
}

std::pair<bool, std::string> match(std::string s, boost::regex e) {
    std::smatch mat;
    
    int flag = 0;
    std::string ret = "";
    while (boost::regex_search(s, mat, e)) {
        for (auto &val:mat) {
            flag = 1;
            ret += val;
            ret + "; ";
        }
        s = mat.suffix().str();
    }
    if (flag) {
        ret.pop_back(); ret.pop_back();
        return std::make_pair(true, ret);
    }
    return std::make_pair(false, "");
}

 
