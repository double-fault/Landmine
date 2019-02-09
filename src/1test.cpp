#include <stdio.h>
#include <algorithm>
#include <functional>
#include <set>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#include "crow.h"

int main(void) {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")([](){
            return "Hello World";
    });

    CROW_ROUTE(app, "/add_json").methods("GET"_method)
    ([](const crow::request& req){
        try {
            auto x = crow::json::load(req.body);
            if (!x)
                return crow::response(400);
            int sum = x["a"].i()+x["b"].i();
            std::ostringstream os;
            os << sum;
            return crow::response{400, os.str()};
        } catch (const std::runtime_error &error) {
            return crow::response{error.what()};
        }
        });

    app.port(80).multithreaded().run();

    return 0;
}

