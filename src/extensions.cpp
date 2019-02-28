/*
 * extensions.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 20th February 2019.
 *
 *
*/

#include <string>
#include <algorithm>
#include <exception>
#include <vector>
#include <set>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

#include "crow.h"
#include "json.hpp"

#include "extensions.h"

namespace ext {
    namespace req {
        const char *missing_question_bool::what() const throw() {
            return "missing field: boolean value \"is_question\" missing in provided json.";
        }

        const char *missing_site::what() const throw() {
            return "missing field: string \"site\" missing in provided json.";
        }

        const char *missing_score::what() const throw() {
            return "missing field: int \"score\" missing in provided json; if score is unknown, include it as -1";
        }

        const char *missing_user_rep::what() const throw() {
            return "missing field: int \"user_rep\" missing in provided json; if rep is unknown, include it as -1";
        }

        const char *missing_body::what() const throw() {
            return "missing field: string \"body\" missing in provided json.";
        }

        const char *missing_username::what() const throw() {
            return "missing field: string \"username\" missing in provided json.";
        }

        const char *missing_type::what() const throw() {
            return "missing field: int \"type\" missing in provided json.";
        }

        const char *missing_title::what() const throw() {
            return "missing field: string \"title\" missing in provided json.";
        }

        const char *missing_api_key::what() const throw() {
            return "No api key was passed.";
        }

        const char *missing_write_token::what() const throw() {
            return "No write token was passed.";
        }
    }

    namespace err {
        const char *invalid_list_identifier::what() const throw() {
            return "invalid list identifier";
        }
    }

    json crow_to_json(crow::json::rvalue crow_json) {
        return json::parse(crow::json::dump(crow_json));
    }

    std::string join(std::vector<std::string> elements, char del) {
        std::string ret;
        for (auto &s:elements) ret += (s + del);
        ret.pop_back(); return ret;
    }

    std::string join(std::set<std::string> elements, char del) {
        std::string ret;
        for (auto &s: elements) ret += (s + del);
        ret.pop_back(); return ret;
    }
}

