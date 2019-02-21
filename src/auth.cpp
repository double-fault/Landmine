/*
 * auth.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 20th February 2019.
 *
 *
*/

#include <string>
#include <algorithm>
#include <fstream>
#include <set>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

#include "auth.h"
#include "extensions.h"

#include "crow.h"
#include "json.hpp"

Auth::Auth(std::string file) {
    data_file = file;
    std::ifstream i(data_file);
    json j; i >> j;

    api_keys.clear(); write_tokens.clear();
    for (const std::string &key: j["api_keys"]) api_keys.insert(key);
    for (const std::string &token: j["write_tokens"]) write_tokens.insert(token);
}

void Auth::save(void) {
    json j;
    j["api_keys"] = json::array(); j["write_tokens"] = json::array();

    for (const std::string &key: api_keys) j["api_keys"].push_back(key);
    for (const std::string &token: write_tokens) j["write_tokens"].push_back(token);

    std::ofstream o(data_file);
    /* Write prettified json to data file */
    o << std::setw(4) << j << std::endl;
}

bool Auth::verify(int clearance_req, crow::json::rvalue req_body) {
    if (clearance_req < API_ACCESS) return true;
    
    json j = ext::crow_to_json(req_body);
    /* Check if the api key exists */
    if (j.find("key") == j.end()) throw ext::req::missing_api_key();
    
    /* Check if key is valid */
    if (api_keys.find(j["key"]) == api_keys.end()) return false;
    if (clearance_req == API_ACCESS) return true;

    /* For those requests which need WRITE_ACCESS */
    if (j.find("write_token") == j.end()) throw ext::req::missing_write_token();

    if (write_tokens.find(j["write_token"]) == write_tokens.end()) return false;
    return true;
}

