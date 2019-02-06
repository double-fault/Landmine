/*
 * findspam.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 23rd January 2019.
 *
 *
*/

#include <cstdio>
#include <string>
#include <cstring>
#include <cstdlib>
#include <algorithm>

#include "json.hpp"
#include "post.h"
#include "findspam.h"

MatchReturn::MatchReturn(bool m, std::string r, std::string w) {
    match = m;
    reason = r;
    why = w;
}

PostFilter::PostFilter(bool _all_sites = true, std::set<std::string> _sites = {},
        bool _question = true, bool _answer = true, int _max_rep = 1, int _max_score = 1) {
    all_sites = _all_sites;
    sites = _sites;
    question = _question;
    answer = _answer;
    max_rep = _max_rep;
    max_score = _max_score;
}

bool PostFilter::match(Post p) {
    if ((p.question && !question) || (!p.question && !answer)) {
        /* Wrong post type */
        return false;
    } else if (!all_sites && sites.find(p.site) == sites.end()) {
        /* Post is on the wrong site */
        return false;
    } else if ((post.user_rep > max_rep) || (post.score > max_score)) {
        /* High rep or high score */
        return false;
    }
    return true;
}

Rule::Rule(std::function<std::vector<MatchReturn>(Post)> _func, int _type, int _priority,
        PostFilter _filter = PostFilter()) {
    func = _func;
    type = _type;
    priority = _priority;
    filter = _filter;
}

std::pair<int, std::vector<MatchReturn>> Rule::run(Post p, int p_type) {
    if (!filter.match(p)) return false;
    if (p_type != type && type != 0) return false;
    return std::make_pair(priority, func(p));
}

FindSpam::FindSpam() {
    /* All spam-checking rules are added here */
    /* _TODO: Add spam rules here, duh! */
}

json FindSpam::test_post(Post p, int post_type) {
    json ret;
    ret["is_spam"] = 0;
    ret["reasons"] = json::array();
    for (auto &rule: rules) {
        std::pair<int, std::vector<MatchReturn>> rule_ret = rule.run(p, post_type);
        for (auto &res: rule_ret.second) {
            if (res.match) {
                ret["is_spam"] = 1;
                json to_insert = json::object();
                to_insert["priority"] = rule_ret.first;
                to_insert["reason"] = res.reason;
                to_insert["why"] = res.why;
                
                ret["reasons"].push_back(to_insert);
            }
        }
    }
    return ret;
}

