/*
 * auth.h
 * Landmine
 *
 * Created by Ashish Ahuja on 20th February 2019.
 *
 *
*/

#ifndef Auth_h
#define Auth_h

#include <string>
#include <algorithm>
#include <fstream>
#include <set>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

#include "crow.h"
#include "json.hpp"

using json = nlohmann::json;

#define API_ACCESS   1
#define WRITE_ACCESS 2

class Auth {
    public:
        Auth(std::string file);
        void save(void);
        bool verify(int clearance_req, crow::json::rvalue req_body);
        bool revoke(std::string key, int type);
    private:
        std::string data_file;

        /* Sets are faster than vectors, especially when doing a search */
        std::set<std::string> api_keys;
        std::set<std::string> write_tokens;
};

#endif /* Auth_h */

