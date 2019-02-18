/*
 * landmine.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 22nd January 2019.
 * 
 *
*/

#include <cstdlib>
#include <algorithm>
#include <exception>
#include <cstdio>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

#include <boost/exception/all.hpp>

#include "crow.h"
#include "json.hpp"

#include "post.h"
#include "findspam.h"
#include "landmine.h"

using json = nlohmann::json;

/* Extensions */

namespace ext {
    /* Exceptions */
    class _missing_question_bool: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: boolean value \"is_question\" missing in provided json.";
        }
    } missing_question_bool;

    class _missing_site: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: string \"site\" missing in provided json.";
        }
    } missing_site;

    class _missing_score: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: int \"score\" missing in provided json; if score is unknown, include it as -1";
        }
    } missing_score;

    class _missing_user_rep: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: int \"user_rep\" missing in provided json; if rep is unknown, include it as -1";
        }
    } missing_user_rep;

    class _missing_body: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: string \"body\" missing in provided json.";
        }
    } missing_body;

    class _missing_username: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: string \"username\" missing in provided json.";
        }
    } missing_username;

    class _missing_type: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: int \"type\" missing in provided json.";
        }
    } missing_type;

    class _missing_title: public std::exception {
        virtual const char* what() const throw() {
            return "missing field: string \"title\" missing in provided json.";
        }
    } missing_title;

    /* Adapting nlohmann::json to crow::response */
    /* From https://github.com/ipkn/crow/issues/263#issuecomment-345588043 */
    struct jsonresponse: crow::response {
        jsonresponse(int _code, const nlohmann::json &_body): crow::response{_code, _body.dump()} {
            add_header("Access-Control-Allow-Origin", "*");
            add_header("Access-COntrol-Allow-Headers", "Content-Type");
            add_header("Content-Type", "application/json");
        }
    };
}

Landmine::Landmine(int app_port) {
    port = app_port;
    spamchecker = FindSpam();
}

Post Landmine::get_post_from_json(crow::json::rvalue crow_json) {
    bool is_question;
    std::string site;
    int score;
    int user_rep;
    std::string body;
    std::string username;
    std::string title;
    int type;

    const std::string key_not_found = "cannot find key";
    try {
        is_question = crow_json["is_question"].b();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_question_bool;
        throw err;
    }

    try {
        site = crow_json["site"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_site;
        throw err;
    }

    try {
        score = crow_json["score"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_score;
        throw err;
    }

    try {
        user_rep = crow_json["user_rep"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_user_rep;
        throw err;
    }

    try {
        body = crow_json["body"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found) 
            throw ext::missing_body;
        throw err;
    }

    try {
        username = crow_json["username"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_username;
        throw err;
    }

    try {
        title = crow_json["title"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_title;
        throw err;
    }

    try {
        type = crow_json["type"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_type;
        throw err;
    }

    return Post(is_question, site, score, user_rep, body, username, title, type);
}

json Landmine::generate_error_json(const std::runtime_error err) {
    json ret;
    ret["error_id"] = 400;
    ret["description"] = err.what();
    ret["error_name"] = "bad_parameter";

    return ret;
}

json Landmine::generate_error_json(const std::exception &err) {
    json ret;
    ret["error_id"] = 400;
    ret["description"] = err.what();
    ret["error_name"] = "bad_parameter";

    return ret;
}

json Landmine::generate_error_json(const std::string err) {
    json ret;
    ret["error_id"] = 500;
    ret["description"] = fmt::sprintf(
            "An error occurred while servicing the request; contact a dev. Error: %s", err);
    ret["error_name"] = "internal_error";

    return ret;
}

void Landmine::init(void) {
    /* To mute info logs */
    /* crow::logger:setLogLevel(crow::LogLevel::Debug); */

    int t = 0;

    CROW_ROUTE(app, "/posts/check")
        .methods("GET"_method)
    ([this](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        Post p(false, "", -1, -1, "", "", "", -1);
        try {
            p = get_post_from_json(crow_json);
        } catch (const std::runtime_error &err) {
            return ext::jsonresponse{400, generate_error_json(err)}; 
        } catch (const std::exception &err) {
            return ext::jsonresponse{400, generate_error_json(err)};
        } catch (...) {
            return ext::jsonresponse{500, generate_error_json(boost::current_exception_diagnostic_information())};
        }

        json ret = spamchecker.test_post(p);
        return ext::jsonresponse{200, ret};
    });
}

void Landmine::start(void) {
    app.port(port)
        .multithreaded().run();
}

void Landmine::stop(void) {
    app.stop();
}

