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
#include <functional>

#include <boost/regex.hpp>

#include "json.hpp"
#include "post.h"
#include "findspam.h"
#include "reasons.h"
#include "regex.h"

MatchReturn::MatchReturn(bool m, std::string r, std::string w) {
    match = m;
    reason = r;
    why = w;
}

PostFilter::PostFilter(bool _all_sites, std::set<std::string> _sites,
        bool _question, bool _answer, int _max_rep, int _max_score) {
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
    } else if (all_sites == (sites.find(p.site) != sites.end())) {
        /* Post is on the wrong site */
        return false;
    } else if ((p.user_rep > max_rep) || (p.score > max_score)) {
        /* High rep or high score */
        return false;
    }
    return true;
}

/* _TODO: stripcodeblocks option */
Rule::Rule(std::function<std::vector<MatchReturn>(Post)> _func, int _type, bool _stripcodeblocks,
        PostFilter _filter) {
    func = _func;
    type = _type;
    stripcodeblocks = _stripcodeblocks;
    filter = _filter;
}

std::vector<MatchReturn> Rule::run(Post p) {
    std::vector<MatchReturn> error_ret(3, MatchReturn(false, "", ""));
    if (!filter.match(p)) {
        return error_ret;
    }
    if (p.type != type && type != 0) return error_ret;

    if (stripcodeblocks) {
        /* use a placeholder to avoid triggering "few unique characters" when most of post is code */
        /* XXX: "few unique characters" doesn't enable this, so remove placeholder? */
        p.body = boost::regex_replace(p.body, code_sub_1, "\ncode\n");
        p.body = boost::regex_replace(p.body, code_sub_2, "\ncode\n");
    }

    return func(p);
}

FindSpam::FindSpam() {
    /* All spam-checking rules are added here */
    rules.push_back(Rule(&misleading_link, 0, true, PostFilter(true, {}, true, true, 10)));
    /*rules.push_back(Rule(&mostly_non_latin, 0, true, PostFilter(true, {
                "stackoverflow.com", "ja.stackoverflow.com", "pt.stackoverflow.com",
                "es.stackoverflow.com", "islam.stackexchange.com", "japanese.stackexchange.com",
                "anime.stackexchange.com", "hinduism.stackexchange.com", "judaism.stackexchange.com",
                "buddhism.stackexchange.com", "chinese.stackexchange.com", "french.stackexchange.com",
                "spanish.stackexchange.com", "portugese.stackexchange.com", "codegolf.stackexchange.com",
                "korean.stackexchange.com", "ukrainian.stackexchange.com"})));*/
    rules.push_back(Rule(&bad_phone_number, 0, true, PostFilter(true, {}, true, true, 5)));
    rules.push_back(Rule(&watched_phone_number, 0, true, PostFilter(true, {}, true, true, 5)));
    rules.push_back(Rule(&blacklisted_username, 1, false, PostFilter()));
    rules.push_back(Rule(&bad_keyword, 0, false, PostFilter(true, {}, true, true, 4)));
    rules.push_back(Rule(&potentially_bad_keyword, 0, false, PostFilter(true, {}, true, true, 30)));
    rules.push_back(Rule(&blacklisted_website, 0, false, PostFilter(true, {}, true, true, 50, 5)));
    rules.push_back(Rule(&repeated_url, 0, true, PostFilter()));
    rules.push_back(Rule(&url_in_title, 1, false, PostFilter(true, {
                "stackoverflow.com", "pt.stackoverflow.com", "ru.stackoverflow.com", 
                "es.stackoverflow.com", "ja.stackoverflow.com", "superuser.com", "askubuntu.com",
                "serverfault.com", "unix.stackexchange.com", "webmaster.stackexchange.com"},
                true, false, 11)));
    rules.push_back(Rule(&url_only_title, 1, false, PostFilter(false, {
                "stackoverflow.com", "pt.stackoverflow.com", "ru.stackoverflow.com",
                "es.stackoverflow.com", "ja.stackoverflow.com", "superuser.com", "askubuntu.com",
                "serverfault.com", "unix.stackexchange.com", "webmaster.stackexchange.com"}, 
                true, false, 11)));
    rules.push_back(Rule(&offensive_post_detected, 0, true, PostFilter(true, {}, true, true, 101, 2)));
    rules.push_back(Rule(&pattern_matching_website, 0, true, PostFilter()));
    rules.push_back(Rule(&ext_1_pattern_matching_website, 0, false, PostFilter(true, {
                "travel.stackexchange.com", "expatriates.stackexchange.com"})));
    rules.push_back(Rule(&ext_2_pattern_matching_website, 0, false, PostFilter(true, {}, false)));
    rules.push_back(Rule(&ext_3_pattern_matching_website, 0, false, PostFilter(true, {
                    "fitness.stackexchange.com", "biology.stackexchange.com", "medicalsciences.stack"
                    "exchange.com", "skeptics.stackexchange.com", "bicycles.stackexchange.com"})));
    //rules.push_back(Rule(&bad_pattern_in_url, 0, true, PostFilter()));
    rules.push_back(Rule(&bad_keyword_with_link, 0, false, PostFilter(true, {}, false)));
    /* _TODO: this doesn't work */
    rules.push_back(Rule(&email_in_answer, 1, true, PostFilter(false, {
                    "biology.stackexchange.com", "bitcoin.stackexchange.com", "ell.stackexchange.com",
                    "english.stackexchange.com", "expatriates.stackexchange.com", "gaming.stackexchange.com",
                    "medicalsciences.stackexchange.com", "money.stackexchange.com", 
                    "parenting.stackexchange.com", "rpg.stackexchange.com", "scifi.stackexchange.com",
                    "travel.stackexchange.com", "worldbuilding.stackexchange.com"}, false)));
    /* _TODO: this doesn't work either */
    rules.push_back(Rule(&email_in_question, 1, true, PostFilter(false, {
                    "biology.stackexchange.com", "bitcoin.stackexchange.com", "ell.stackexchange.com",
                    "english.stackexchange.com", "expatriates.stackexchange.com", "gaming.stackexchange.com",
                    "medicalsciences.stackexchange.com", "money.stackexchange.com",
                    "parenting.stackexchange.com", "rpg.stackexchange.com", "scifi.stackexchange.com",
                    "travel.stackexchange.com", "worldbuilding.stackexchange.com"}, true, false)));
    rules.push_back(Rule(&linked_punctuation, 0, true, PostFilter(true, {"codegolf.stackexchange.com"},
                    false, true, 11)));
    /* _TODO: *sigh* not working either */
    rules.push_back(Rule(&link_following_arrow, 1, false, PostFilter(true, {}, true, false, 11)));
    rules.push_back(Rule(&link_at_end_2, 1, false, PostFilter(true, {
                    "raspberrypi.stackexchange.com", "softwarerecs.stackexchange.com"}, false)));
    rules.push_back(Rule(&link_at_end_3, 1, false, PostFilter(true, {}, false)));
    rules.push_back(Rule(&shortened_url_question, 1, false, PostFilter(true, {
                    "superuser.com", "askubuntu.com"}, false)));
    rules.push_back(Rule(&shortened_url_answer, 1, true, PostFilter(true, {"codegolf.stackexchange.com"},
                    false)));
    rules.push_back(Rule(&no_whitespace, 0, false, PostFilter(true, {}, true, true, 10000, 10000)));
    rules.push_back(Rule(&messaging_number_detected, 0, true, PostFilter()));
    rules.push_back(Rule(&numbers_only_title, 0, false, PostFilter(true, {"math.stackexchange.com"},
                    true, false, 50, 5)));
    rules.push_back(Rule(&one_unique_char_in_title, 0, false, PostFilter(true, {}, true, false, 1000000, 100000)));
    rules.push_back(Rule(&link_inside_nested_blockquotes, 0, true, PostFilter()));
    rules.push_back(Rule(&comma_at_title_end, 1, false, PostFilter(false, {
                    "interpersonal.stackexchange.com"}, true, false, 50)));
    rules.push_back(Rule(&title_starts_and_ends_with_slash, 0, false, PostFilter(true, {}, true, false)));
    rules.push_back(Rule(&exc_blacklisted_username_1, 1, false, PostFilter(false, {"drupal.stackexchange.com"})));
    rules.push_back(Rule(&exc_blacklisted_username_2, 1, false, PostFilter(false, {
                    "parenting.stackexchange.com"})));
    rules.push_back(Rule(&exc_blacklisted_username_3, 1, false, PostFilter(false, {"judaism.stackexchange.com"})));
    rules.push_back(Rule(&exc_blacklisted_username_4, 1, false, PostFilter(false, {
                    "hinduism.stackexchange.com", "judaism.stackexchange.com", "islam.stackexchange.com"}
                    )));
}

json FindSpam::test_post(Post p) {
    json ret; int idx = 0;
    ret["is_spam"] = 0;
    ret["reasons"] = json::array();
    for (auto &rule: rules) {
        std::vector<MatchReturn> rule_ret = rule.run(p);
        for (auto &res: rule_ret) {
            if (res.match) {
                ret["is_spam"] = 1;
                json to_insert = json::object();
                to_insert["idx"] = idx;
                to_insert["reason"] = res.reason;
                to_insert["why"] = res.why;

                ret["reasons"].push_back(to_insert);
            }
        }
    }
    return ret;
}

