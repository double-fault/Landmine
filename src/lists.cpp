/*
 * lists.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 *
*/

#include <algorithm>
#include <fstream>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

#include <boost/regex.hpp>

#include "json.hpp"
#include "findspam.h"
#include "post.h"
#include "lists.h"
#include "extensions.h"

List::List() {}

void List::init(json o) {
    int flag = 0;
    for (const std::string &ele: o) {
        flag = 1;
        elements.insert(ele);
    }
    for (const std::string &ele: elements) {
        fmt::print("{}\n", ele);
    }
}

void List::add(std::string s) {
    puts("inserting");
    elements.insert(s);
    for (const std::string &s: elements) fmt::print("{}\n", s);
}

void List::remove(std::string s) {
    puts("removing");
    elements.erase(s);
}

std::string List::get_consolidated_string(void) { 
    std::string ret;
    for (const std::string &s: elements) ret += s + '|';
    if (ret.length() > 0) ret.pop_back();
    return ret;
}

Lists::Lists(std::string file) {
    data_file = file;
    std::ifstream i(data_file);
    json j;
    i >> j;

    bad_keywords.init(j["bad_keywords"]);
    bad_keywords_nwb.init(j["bad_keywords_nwb"]);
    watched_keywords.init(j["watched_keywords"]);
    blacklisted_websites.init(j["blacklisted_websites"]);
    blacklisted_usernames.init(j["blacklisted_usernames"]);
    blacklisted_numbers.init(j["blacklisted_numbers"]);
    watched_numbers.init(j["watched_numbers"]);

    reload();
}

void Lists::reload(void) {
    std::string temp = "(?is)(?:^|\\b)(?:%s)(?:\\b|$)|%s"; 
    r_bad_keywords = (fmt::sprintf(temp, bad_keywords.get_consolidated_string(),
                bad_keywords_nwb.get_consolidated_string()));

    temp = "(?is)(?:^|\\b)(?:%s)(?:\\b|$)";
    r_watched_keywords = (fmt::sprintf(temp, watched_keywords.get_consolidated_string()));

    temp = "(?i)(%s)";
    r_blacklisted_websites = (fmt::sprintf(temp, blacklisted_websites.get_consolidated_string()));

    temp = "(?i)(%s)";
    r_blacklisted_usernames = (fmt::sprintf(temp, blacklisted_usernames.get_consolidated_string()));

    r_numbers = boost::regex("((?<=\\D)|^)\\+?(?:\\d[\\W_]*){8,13}\\d(?=\\D|$)", boost::regex::icase);

    const boost::regex e ("\\D");
    for (auto &num: blacklisted_numbers.elements) {
        bad_numbers_pair.first.insert(num);
        bad_numbers_pair.second.insert(boost::regex_replace(num, e, ""));
    }
    for (auto &num: watched_numbers.elements) {
        watched_numbers_pair.first.insert(num);
        watched_numbers_pair.second.insert(boost::regex_replace(num, e, ""));
    }
}

void Lists::save(void) {
    json j;

    j["bad_keywords"] = json::array(); j["bad_keywords_nwb"] = json::array();
    j["watched_keywords"] = json::array(); j["blacklisted_websites"] = json::array();
    j["blacklisted_usernames"] = json::array();
    j["blacklisted_numbers"] = json::array(); j["watched_numbers"] = json::array();

    for (const std::string &s: bad_keywords.elements) j["bad_keywords"].push_back(s);
    for (const std::string &s: bad_keywords_nwb.elements) j["bad_keywords_nwb"].push_back(s);
    for (const std::string &s: watched_keywords.elements) j["watched_keywords"].push_back(s);
    for (const std::string &s: blacklisted_websites.elements) j["blacklisted_websites"].push_back(s);
    for (const std::string &s: blacklisted_usernames.elements) j["blacklisted_usernames"].push_back(s);
    for (const std::string &s: blacklisted_numbers.elements) j["blacklisted_numbers"].push_back(s);
    for (const std::string &s: watched_numbers.elements) j["watched_numbers"].push_back(s);

    /* _TODO: Handle cases where the file doesn't exist (does it matter when we are writing?) */
    std::ofstream o(data_file);
    o << std::setw(4) << j << std::endl;
}

List *Lists::get_list_from_identifier(std::string type) {
    if (type == "bad_keywords")
        return &bad_keywords;
    if (type == "bad_keywords_nwb")
        return &bad_keywords_nwb;
    if (type == "watched_keywords")
        return &watched_keywords;
    if (type == "blacklisted_websites")
        return &blacklisted_websites;
    if (type == "blacklisted_usernames")
        return &blacklisted_usernames;
    if (type == "blacklisted_numbers")
        return &blacklisted_numbers;
    if (type == "watched_numbers")
        return &watched_numbers;
    throw ext::err::invalid_list_identifier();
}

/* This func throws ext::err::invalid_list_identifier from std::exception */
void Lists::add(std::string to_add, std::string ident) {
    List *l = get_list_from_identifier(ident);
    l->add(to_add);

    reload();
    save();
}

bool Lists::remove(std::string to_remove, std::string ident) {
    List *l = get_list_from_identifier(ident);
    if (l->elements.find(to_remove) == l->elements.end()) return false;
    l->remove(to_remove);

    reload();
    save();

    return true;
}

std::pair<bool, std::string> match(std::string s, boost::regex e) {
    boost::smatch mat;
    
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

 

