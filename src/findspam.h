/*
 * findspam.h
 * Landmine
 *
 * Created by Ashish Ahuja on 23rd January 2019.
 *
 *
*/

#ifndef Findspam_h
#define Findspam_h

#include <cstdlib>
#include <string>
#include <algorithm>

#include "json.hpp"
#include "post.h"

using json = nlohmann::json;

class MatchReturn {
    public:
        MatchReturn(bool m, std::string r, std::string w);
        bool match;
        std::string reason;
        std::string why;
}

/* General filter for SE posts */
class PostFilter {
    public:
        PostFilter(bool _all_sites = true, std::set<std::string> _sites = {}, 
                bool _question = true, bool _answer = true, int _max_rep = 1, int _max_score = 1);
        bool match(Post p);
    private:
        std::set<std::string> sites;
        bool all_sites;
        int max_rep;
        int max_score;
        bool question;
        bool answer;
}

class Rule {
    public:
        Rule(std::function<std::vector<MatchReturn>(Post)> _func, int _type, int _priority,
                PostFilter _filter = PostFilter());
        std::pair<int, std::vector<MatchReturn>> run(Post p, int type);
    private:
        /* First element is for title check, second for body check, third for username check */
        std::function<std::vector<MatchReturn>(Post)> func;
        PostFilter filter;
        int type;           /* 0 for all posts */
        int priority;       /* 0 for experimental reasons, 1 for all others */
}

class FindSpam {
    public:
        FindSpam();
        json FindSpam::test_post(Post p, int post_type);
    private:
        std::vector<Rule> rules;
}

#endif /* Findspam_h */

