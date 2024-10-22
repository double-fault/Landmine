/*
 * landmine.h
 * Landmine
 *
 * Created by Ashish Ahuja on 9th February 2019.
 *
 *
*/

#ifndef Landmine_h
#define Landmine_h

#include <cstdlib>
#include <algorithm>
#include <exception>

#include "crow.h"
#include "json.hpp"

#include "post.h"
#include "findspam.h"
#include "lists.h"
#include "extensions.h"
#include "auth.h"

using json = nlohmann::json;

class Landmine {
    public:
        Landmine(int app_port);
        void init(void);
        void start(void);
        void stop(void);
    private:
        crow::SimpleApp app; /* To stop: app.stop(); */
        int port;
        Post get_post_from_json(crow::json::rvalue crow_json);
        json generate_error_json(const std::runtime_error err);
        json generate_error_json(const std::exception &err);
        json generate_error_json(const std::string err);
        json generate_error_json(int error_id, std::string desc, std::string error_name);
        FindSpam spamchecker;
        Auth auth;
        std::pair<bool, json> authenticate(int clearance_req, crow::json::rvalue crow_json);
        std::pair<bool, json> required_params(std::vector<std::string> params, json body);
};

#endif /* Landmine_h */

