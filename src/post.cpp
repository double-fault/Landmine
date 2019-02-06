/*
 * post.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 25th January 2019.
 *
 *
*/

#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <string>

#include "Post.h"

Post::Post(bool _question, std::string _site, int _score, int _user_rep,
        std::string _body, std::string _username, std::string _title = "") {
    question = _question;
    site = _site;
    score = _score;
    user_rep = _user_rep;
    body = _body;
    username = _username;
    title = _title;
}

