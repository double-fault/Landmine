/*
 * post.h
 * Landmine
 *
 * Created by Ashish Ahuja on 25th January 2019.
 *
 *
*/

#ifndef Post_h
#define Command_h

#include <cstdio>
#include <cstdlib>
#include <string>
#include <algorithm>

class Post {
    public:
        Post(bool _question, std::string _site, int _score, int _user_rep,
                std::string _body, std::string _username, std::string _title = "");
    private:
        bool question;
        std::string site;
        int score;
        int user_rep;
        std::string body;
        std::string username;
        std::string title;
}

#endif /* Post_h */

