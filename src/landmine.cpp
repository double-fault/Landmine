/*
 * landmine.cpp
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
#include <exception>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include "crow.h"
#include "json.hpp"

#include "post.h"
#include "findspam.h"

using json = nlohmann::json;

/* Extensions */

namespace ext {
    /* Exceptions */
    class missing_question_bool: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: boolean value \"is_question\" missing in provided json.";
        }
    }

    class missing_site: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: string \"site\" missing in provided json.";
        }
    }

    class missing_score: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: int \"score\" missing in provided json; if score is unknown, include it as -1";
        }
    }

    class missing_user_rep: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: int \"user_rep\" missing in provided json; if rep is unknown, include it as -1";
        }
    }

    class missing_body: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: string \"body\" missing in provided json.";
        }
    }

    class missing_username: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: string \"username\" missing in provided json.";
        }
    }

    class missing_type: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: int \"type\" missing in provided json.";
        }
    }

    class missing_title: public std::runtime_error {
        virtual const char* what() const throw() {
            return "missing field: string \"title\" missing in provided json.";
        }
    }

    /* Adapting nlohmann::json to crow::response */
    /* From https://github.com/ipkn/crow/issues/263#issuecomment-345588043 */
    struct jsonresponse: crow::response {
        jsonresponse(int _code, const nlohmann::json &_body): crow::response{_code, _body.dump()} {
            add_header("Access-Control-Allow-Origin", "*");
            add_header("Access-COntrol-Allow-Headers", "Content-Type");
            add_header("Content-Type", "application/json");
        }
    }
}

class Landmine {
    public:
        Landmine(int app_port);
        void init(void);
        void start(void);
        void stop(void);
    private:
        crow::SimpleApp app; /* To stop: app.stop(); */
        int port;
        Post get_post_from_json(auto crow_json);
        json generate_error_json(const std::runtime_error err);
        json generate_error_json(const std::string err);
        FindSpam spamchecker;
}

Landmine::Landmine(int app_port) {
    port = app_port;
    spamchecker = FindSpam();
}

Post Landmine::get_post_from_json(auto crow_json) {
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
        is_question = crow_json["is_question"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_is_question;
        throw err;
    }

    try {
        site = crow_json["site"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_site;
        throw err;
    }

    try {
        score = crow_json["score"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_score;
        throw err;
    }

    try {
        user_rep = crow_json["user_rep"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_user_rep;
        throw err;
    }

    try {
        body = crow_json["body"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found) 
            throw ext::missing_body;
        throw err;
    }

    try {
        username = crow_json["username"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_username;
        throw err;
    }

    try {
        title = crow_json["title"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_title;
        throw err;
    }

    try {
        type = crow_json["type"];
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::missing_type;
        throw err;
    }

    return Post(is_question, site, score, user_rep, body, username, type, title);
}

json Landmine::generate_error_json(const std::runtime_error err) {
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

    CROW_ROUTE(app, "/posts/check")
    ([](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        try {
            Post p = get_post_from_json(crow_json);
        } catch (const std::runtime_error &err) {
            return ext::jsonresponse(400, generate_error_json(err)); 
        } catch (...) {
            return ext::jsonresponse(500, generate_error_json(err.what()));
        }

        json ret = spamchecker.test_post(p);
        return ext::jsonresponse(200, ret);
    });
}

void Landmine::start(void) {
    app.port(port)
        .multithreaded().run();
}

void Landmine::stop(void) {
    app.stop();
}

