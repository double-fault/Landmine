/*
 * extensions.h
 * Landmine
 *
 * Created by Ashish Ahuja on 20th February 2019.
 *
 *
*/

#ifndef Extensions_h
#define Extensions_h

#include <string>
#include <algorithm>
#include <exception>

#include "crow.h"
#include "json.hpp"

using json = nlohmann::json;

/* All extensions */
namespace ext {
    /* Custom errors */
    
    /* nested namespace for malformed requests errors */
    namespace req {
        class missing_question_bool: public std::exception {
            virtual const char *what() const throw();
        };
        
        class missing_site: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_score: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_user_rep: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_body: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_username: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_type: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_title: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_api_key: public std::exception {
            virtual const char *what() const throw();
        };

        class missing_write_token: public std::exception {
            virtual const char *what() const throw();
        };
    }

    /* Error extensions end */

    /* API Response */
    namespace resp {
        struct jsonresponse: crow::response {
            jsonresponse(int _code, const nlohmann::json &_body): crow::response{_code, _body.dump()} {
                add_header("Access-Control-Allow-Origin", "*");
                add_header("Access-COntrol-Allow-Headers", "Content-Type");
                add_header("Content-Type", "application/json");
            }
        };
    }

    /* Miscellaneous errors */
    namespace err {
        class invalid_list_identifier: public std::exception {
            virtual const char *what() const throw();
        };
    }

    /* Utilities */
    json crow_to_json(crow::json::rvalue crow_json);
    std::string join(std::vector<std::string> elements, char del);
    std::string join(std::set<std::string> elements, char del);
}

#endif /* Extensions_h */

