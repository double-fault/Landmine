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
#include "extensions.h"
#include "regex.h"

using json = nlohmann::json;

Landmine::Landmine(int app_port): auth("auth.json") {
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
            throw ext::req::missing_question_bool();
        throw err;
    }

    try {
        site = crow_json["site"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_site();
        throw err;
    }

    try {
        score = crow_json["score"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_score();
        throw err;
    }

    try {
        user_rep = crow_json["user_rep"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_user_rep();
        throw err;
    }

    try {
        body = crow_json["body"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found) 
            throw ext::req::missing_body();
        throw err;
    }

    try {
        username = crow_json["username"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_username();
        throw err;
    }

    try {
        title = crow_json["title"].s();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_title();
        throw err;
    }

    try {
        type = crow_json["type"].i();
    } catch (const std::runtime_error &err) {
        if (err.what() == key_not_found)
            throw ext::req::missing_type();
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

json Landmine::generate_error_json(int error_id, std::string desc, std::string error_name) {
    json ret;
    ret["error_id"] = error_id;
    ret["description"] = desc;
    ret["error_name"] = error_name;

    return ret;
}

std::pair<bool, json> Landmine::authenticate(
        int clearance_req, crow::json::rvalue crow_json) {
    bool retv;
    try {
        retv = auth.verify(clearance_req, crow_json);
    } catch (const std::exception &err) {
        return std::make_pair(false, generate_error_json(401, err.what(), "missing_key"));
    }
    if (retv)
        /* Messy hack */
        return std::make_pair(true,
                generate_error_json(200, "fuck; there is a bug. Contact a dev", "wtf"));
    return std::make_pair(false, 
            generate_error_json(402, "Invalid api key or write token.", "invalid_key"));
}

std::pair<bool, json> Landmine::required_params(std::vector<std::string> params, json body) {
    for (const std::string &p: params) {
        if (body.find(p) == body.end())
            return std::make_pair(false, generate_error_json(400,
                        fmt::sprintf("missing field: \"%s\"", p), "bad_parameter"));
    }
    return std::make_pair(true,
            generate_error_json(200, "the fuck", "wtf"));
}

void Landmine::init(void) {
    /* To mute info logs */
    /* crow::logger:setLogLevel(crow::LogLevel::Debug); */

    int t = 0;

    CROW_ROUTE(app, "/posts/check")
        .methods("GET"_method)
    ([this](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        std::pair<bool, json> eret = authenticate(API_ACCESS, crow_json);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        Post p(false, "", -1, -1, "", "", "", -1);
        try {
            p = get_post_from_json(crow_json);
        } catch (const std::runtime_error &err) {
            return ext::resp::jsonresponse{400, generate_error_json(err)}; 
        } catch (const std::exception &err) {
            return ext::resp::jsonresponse{400, generate_error_json(err)};
        } catch (...) {
            return ext::resp::jsonresponse{500, 
                generate_error_json(boost::current_exception_diagnostic_information())};
        }

        json ret = spamchecker.test_post(p);
        return ext::resp::jsonresponse{200, ret};
    });

    CROW_ROUTE(app, "/keys/revoke")
        .methods("DELETE"_method)
    ([this](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        std::pair<bool, json> eret = authenticate(API_ACCESS, crow_json);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        json j = ext::crow_to_json(crow_json);
        eret = required_params({"type"}, j);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        if (j["type"] == API_ACCESS)
            auth.revoke(j["key"], API_ACCESS);
        else if (j["type"] == WRITE_ACCESS) {
            eret = authenticate(WRITE_ACCESS, crow_json);
            if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};
            auth.revoke(j["write_token"], WRITE_ACCESS);
        } else
            return ext::resp::jsonresponse{400, generate_error_json(400,
                    fmt::sprintf("Invalid type %d.", j["type"]), "bad_parameter")};
        json ret;
        ret["status"] = "Key revoked.";
        return ext::resp::jsonresponse{200, ret};
    });

    CROW_ROUTE(app, "/blacklists/add")
        .methods("POST"_method)
    ([this](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        std::pair<bool, json> eret = authenticate(WRITE_ACCESS, crow_json);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        json j = ext::crow_to_json(crow_json);
        eret = required_params({"regex", "identifier"}, j);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        try {
            all_lists.add(j["regex"], j["identifier"]);
        } catch (const std::exception &err) {
            return ext::resp::jsonresponse{400, generate_error_json(err)};
        }
        json ret;
        ret["status"] = "Regex added.";
        return ext::resp::jsonresponse{200, ret};
    });

    CROW_ROUTE(app, "/blacklists/remove")
        .methods("POST"_method)
    ([this](const crow::request &req) {
        auto crow_json = crow::json::load(req.body);

        std::pair<bool, json> eret = authenticate(WRITE_ACCESS, crow_json);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        json j = ext::crow_to_json(crow_json);
        eret = required_params({"regex", "identifier"}, j);
        if (!eret.first) return ext::resp::jsonresponse{eret.second["error_id"], eret.second};

        try {
            bool ret = all_lists.remove(j["regex"], j["identifier"]);
            if (!ret)
                return ext::resp::jsonresponse{400, generate_error_json(400, 
                        "regex does not exist in list", "bad_parameter")};
        } catch (const std::exception &err) {
            return ext::resp::jsonresponse{400, generate_error_json(err)};
        }
        json ret;
        ret["status"] = "Regex removed.";
        return ext::resp::jsonresponse{200, ret};
    });

    CROW_ROUTE(app, "/alive")
        .methods("GET"_method)
        ([this](const crow::request &req) {
         return "Tick Tock. This Landmine is live; try not to step on it now, will you?";
    });
}

void Landmine::start(void) {
    app.port(port)
        .multithreaded().run();
}

void Landmine::stop(void) {
    app.stop();
}

