/* 
 * lists.h
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 *
 *
*/

#ifndef Lists_h
#define Lists_h

#include <cstdio>
#include <cstdlib>
#include <algorithm>

#include <boost/regex.hpp>

#include "post.h"
#include "json.hpp"
#include "findspam.h"

using json = nlohmann::json;

class List {
    public:
        List();
        void init(json o);
        std::string get_consolidated_string(void);
        std::vector<std::string> elements;
    private:
        std::string consolidated;
}

class Lists {
    public:
        Lists(std::string file);
        std::pair<bool, std::pair<std::string, int>>  
    private:
        std::string data_file;

        List bad_keywords;
        List bad_keywords_nwb;
        List watched_keywords;
        List blacklisted_websites;
        List blacklisted_usernames;
        List blacklisted_numbers;
        List watched_numbers;

        boost::regex r_bad_keywords;
        boost::regex r_watched_keywords;
        boost::regex r_blacklisted_websites;
        boost::regex r_blacklisted_usernames;
        boost::regex r_numbers ("(?<=\D|^)\+?(?:\d[\W_]*){8,13}\d(?=\D|$)");

        /* Sets are faster than Hong Kong journalists! */
        /* First set is for processed numbers, second for normalized ones */
        std::pair<std::set<std::string>, std::set<std::string>> bad_numbers_normalized;
        std::pair<std::set<std::string>, std::set<std::string>> watched_numbers_normalized;

        std::pair<bool, std::string> match(std::string s, boost::regex e);
}

#endif /* Lists_h */

