/*
 * filters.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 *
 *
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <functional>

#include "rapidjson/rapidjson.h"

using json = nlohmann:json;

class Filters {
    public:
        Filters(void);
        void add_filter(std::string desc, 
                std::function<std::pair<bool, std::pair<std::string, int>>(std::string)> callback);
        std::string check(std::string body);
    private:
        std::vector<std::pair<std::string,
            std::function<std::pair<bool, std::pair<std::string, int>>(std::string)> callback>> filters;
}

Filters::Filters(void) { }

Filters::add_filter(std::string desc,
        std::function<std::pair<bool, std::pair<std::string, int>>(std::string)> callback) {
    filters.push_back(std::make_pair(desc, callback));
}

std::string check(std::string body) {
    json ret;
    ret["reasons"] = json::array();
    for (auto const& fil: filters) {
        std::pair<bool, std::pair<std::string, int>> res = fil.second(body);
        if (res.first == true) {
            json t = {"desc": fil.first, "keyword": res.second.first, "priority": res.second.second};
            ret["reasons"].push_back(t);
        }
    }
    return ret.dump();
}

