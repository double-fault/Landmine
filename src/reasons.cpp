/*
 * reasons.cpp
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
#include <vector>

/* Boost should considerably bloat up this software, but std::regex currently only supports
 * ECMAScript, so we have no option (other than manually changing thousands of regexes) */
#include <boost/regex.hpp>

#include <fmt/format.h>
#include <fmt/core.h>
#include <fmt/printf.h>

/* Faup */
#include <faup/faup.h>
#include <faup/decode.h>
#include <faup/options.h>
#include <faup/output.h>

#include "post.h"
#include "findspam.h"
#include "regex.h"
#include "extensions.h"

#define LEVEN_DOMAIN_DISTANCE 3

/* _TODO: Create a global Lists object and add it to the to-be-created header file.
 *        Name the Lists object `all_lists`
 */

/* Utility functions */
/* _TODO: include these utility functions in the to-be-made header file as well */

bool is_answer(Post p) {
    if (p.title.empty()) return true;
    return false;
}

std::string get_position(boost::smatch m) {
    int p = m.position();
    std::string ret = fmt::sprintf("Position %d-%d: ", p, p + m[0].length());
    ret += m[0];
    return ret;
}

std::string get_positions(std::vector<boost::smatch> matches) {
    std::string ret;
    bool flag = false;
    for (auto &m:matches) {
        if (flag) ret += ", ";
        flag = true;
        ret += get_position(m);
    }
    return ret;
}

bool is_whitelisted_website(std::string url) {
    boost::smatch m;
    if (boost::regex_search(url, m, whitelisted_websites_regex)) return true;
    return false;
}

/* The following function has been copied from https://rosettacode.org/wiki/Levenshtein_distance#C.2B.2B<Paste> */
/* The next 47 lines are licensed under GNU Free Documentation License 1.2, as mentioned
 * in the Rosetta Code footer.
 * http://www.gnu.org/licenses/fdl-1.2.html
 */

// Compute Levenshtein Distance
// Martin Ettl, 2012-10-05
size_t levenshtein(const std::string &s1, const std::string &s2)
{
  const size_t m(s1.size());
  const size_t n(s2.size());
 
  if( m==0 ) return n;
  if( n==0 ) return m;
 
  size_t *costs = new size_t[n + 1];
 
  for( size_t k=0; k<=n; k++ ) costs[k] = k;
 
  size_t i = 0;
  for ( std::string::const_iterator it1 = s1.begin(); it1 != s1.end(); ++it1, ++i )
  {
    costs[0] = i+1;
    size_t corner = i;
 
    size_t j = 0;
    for ( std::string::const_iterator it2 = s2.begin(); it2 != s2.end(); ++it2, ++j )
    {
      size_t upper = costs[j+1];
      if( *it1 == *it2 )
      {
		  costs[j+1] = corner;
	  }
      else
	  {
		size_t t(upper < corner?upper:corner);
        costs[j+1] = (costs[j] < t?costs[j]:t)+1;
	  }
 
      corner = upper;
    }
  }
 
  size_t result = costs[n];
  delete [] costs;
 
  return result;
}

/* Faup init function */
faup_options_t *faup_start(void) {
    faup_options_t *faup_opts;
    faup_opts = faup_options_new();
    faup_opts->output = FAUP_OUTPUT_NONE;
    faup_opts->exec_modules = FAUP_MODULES_NOEXEC;

    return faup_opts;
}

faup_options_t *faup_opts = faup_start();

/* Returns the extracted domain name without the tld (top-level domain) */
std::string get_domain_without_tld(std::string url) {
    /* fh is a pointer to a c struct that has, among others, all the positions where the uri splits in host, tld, etc.*/
    faup_handler_t *fh;

    if (!faup_opts) {
        /* Error: faup options have not been allocated */
        return url;
    }

    /* init the faup handler */
    fh = faup_init(faup_opts);

    /* Computes the locations of all needed values */
    faup_decode(fh, url.c_str(), url.size());

    std::string ret = url.substr(faup_get_domain_without_tld_pos(fh), faup_get_domain_without_tld_size(fh));

    /* cleanup */
    faup_terminate(fh);
    return ret;
}

/* Return the first level domain of a given url (i.e, the domain name with tld) */
std::string get_fld(std::string url) {
    faup_handler_t *fh;

    if (!faup_opts) {
        /* Error: faup options have not been allocated */
        return url;
    }

    fh = faup_init(faup_opts);
    faup_decode(fh, url.c_str(), url.size());

    std::string ret = url.substr(faup_get_domain_pos(fh), faup_get_domain_size(fh));
    
    faup_terminate(fh);
    return ret;
}

/* Returns true is the string contains a space */
bool check_for_space(std::string s) {
    return (std::count(s.begin(), s.end(), ' ') > 0);
}

/* -------------------------------------------------------------------------------- */
/* The giant rule registry.                                                         */
/* -------------------------------------------------------------------------------- */

/*
 * misleading link
 *
 * title = false
 * max_rep = 10
 * max_score = 1
 * stripcodeblocks = true
 * type = 0 (general)
 */
std::vector<MatchReturn> misleading_link(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));
    if (p.body.empty()) return ret;

    boost::smatch m;
    if (!boost::regex_search(p.body, m, link_re)) return ret;

    std::string href = m[1];
    std::string text = m[2];
    
    std::string href_fld = get_fld(href);
    std::string text_fld = get_fld(text);
    if (boost::regex_match(href_fld, se_sites_re)) return ret;

    /* if `href` is an invalid url, or another error occurs, the return values will be the same as
     * the passed string. Check for this */
    //if (href_fld == href || check_for_space(href_fld)) return ret;

    std::string href_domain = get_domain_without_tld(href);
    if (href_domain == href || check_for_space(href_domain)) return ret;

    std::string text_domain = get_domain_without_tld(text);
    if (text_domain == text || check_for_space(text_domain)) return ret;

    if (levenshtein(href_domain, text_domain) > LEVEN_DOMAIN_DISTANCE)
        ret[1] = MatchReturn(true, "misleading link", 
                    fmt::sprintf("Domain %s indicated by possible misleading text %s.", href_fld, text_fld));
    return ret;
}

/* _TODO: repeating words in %s */
/* _TODO: few unique characters in %s */
/* _TODO: repeating characters in %s */

/* _TODO: non-English link in answer */
/* ^^^: looks like it has been discontinued, but is still present in Smokey's code? */

/*
 * mostly non-Latin %s
 * majority of post is in non-Latin, non-Cyrillic characters
 *
 * stripcodeblocks = true
 * exempt-sites = stackoverflow.com, ja.stackoverflow.com, pt.stackoverflow.com, es.stackoverflow.com,
 *                islam.stackexchange.com, japanese.stackexchange.com, anime.stackexchange.com,
 *                hinduism.stackexchange.com, judaism.stackexchange.com, buddhism.stackexchange.com,
 *                chinese.stackexchange.com, french.stackexchange.com, spanish.stackexchange.com,
 *                portugese.stackexchange.com, codegolf.stackexchange.com, korean.stackexchange.com,
 *                ukrainian.stackexchange.com
 * type = 0
 */
/* _TODO: fix the regex here */
/*
std::vector<MatchReturn> mostly_non_latin(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));
    
    if (!p.title.empty()) {
        std::string word_chars_title = boost::regex_replace(p.title, word_chars_r, "");
        std::string non_latin_title = boost::regex_replace(word_chars_title, non_latin_r, "");
        if (non_latin_title.length() > (0.4 * word_chars_title.length()))
            ret[0] = MatchReturn(true, "mostly non-Latin title", 
                        fmt::sprintf("Text contains %d non-Latin characters out of %d", 
                            non_latin_title.length(), word_chars_title.length()));
    }
    if (!p.body.empty()) {
        std::string word_chars = boost::regex_replace(p.body, word_chars_r, "");
        std::string non_latin_chars = boost::regex_replace(p.body, non_latin_r, "");
        if (non_latin_chars.length() > (0.4 * word_chars.length())) {
            ret[1] = MatchReturn(true, "mostly non-Latin body",
                        fmt::sprintf("Text contains %d non-Latin characters out of %d",
                            non_latin_chars.length(), word_chars.length()));
            if (is_answer(p))
                ret[1].reason = "mostly non-Latin answer";
        }
    }
    return ret;
} */

/* Utility function for checking numbers.
 * Since this is pretty much a filter, it doesn't fall in the utilities section */
std::pair<bool, std::string> check_numbers(std::string s, std::set<std::string> numlist,
        std::set<std::string> numlist_normalized) {
    std::vector<std::string> matches; bool match = false;
    std::string::const_iterator s_iter(s.cbegin());
    boost::smatch m;
    while (boost::regex_search(s_iter, s.cend(), m, all_lists.r_numbers)) {
        if (numlist.find(m[0]) != numlist.end()) {
            match = true; matches.push_back(fmt::sprintf("%s found verbatim.", m[0]));
            s_iter = m.suffix().first;
            continue;
        }
        std::string t = m[0];
        std::string normalized_candidate = boost::regex_replace(t, all_but_digits_re, ""); 
        if (numlist_normalized.find(normalized_candidate) != numlist_normalized.end()) {
            match = true; matches.push_back(fmt::sprintf("%s found normalized.", normalized_candidate));
        }

        s_iter = m.suffix().first;
    }
    if (match) 
        return std::make_pair(true, ext::join(matches, ';'));
    return std::make_pair(false, "");
}

/*
 * bad phone number in %s
 *
 * max_rep = 5
 * max_score = 1
 * stripcodeblocks = true
 * sites = all
 */
std::vector<MatchReturn> bad_phone_number(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));

    if (!p.title.empty()) {
        std::pair<bool, std::string> res = check_numbers(p.title,
                all_lists.bad_numbers_pair.first, all_lists.bad_numbers_pair.second);
        if (res.first) 
            ret[0] = MatchReturn(true, "bad phone number in title", "Title - " + res.second);
    }
    if (!p.body.empty()) {
        std::pair<bool, std::string> res = check_numbers(p.body,
                all_lists.bad_numbers_pair.first, all_lists.bad_numbers_pair.second);
        if (res.first) {
            ret[1] = MatchReturn(true, "bad phone number in body", "Body - " + res.second);
            if (is_answer(p))
                ret[1].reason = "bad phone number in answer";
        }
    }
    return ret;
}

/* _TODO: the two phone number detected in %s filters */
/* Make sure the strip out some html tags: */
/* body_to_check = regex.sub("<(?:a|img)[^>]+>", "", body_to_check) */

/*
 * potentially bad keyword in %s
 * Checks for a potentially bad number
 *
 * max_rep = 5
 * max_score = 1
 * stripcodeblocks = true
 * sites = all
 */
std::vector<MatchReturn> watched_phone_number(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));

    if (!p.title.empty()) {
        std::pair<bool, std::string> res = check_numbers(p.title,
                all_lists.watched_numbers_pair.first, all_lists.watched_numbers_pair.second);
        if (res.first) 
            ret[0] = MatchReturn(true, "potentially bad keyword in title", "Title - " + res.second);
    }
    if (!p.body.empty()) {
        std::pair<bool, std::string> res = check_numbers(p.body,
                all_lists.watched_numbers_pair.first, all_lists.watched_numbers_pair.second);
        if (res.first) {
            ret[1] = MatchReturn(true, "potentially bad keyword in body", "Body - " + res.second);
            if (is_answer(p))
                ret[1].reason = "potentially bad keyword in answer";
        }
    }
    return ret;
}

/*
 * blacklisted Username
 *
 * username = true
 * title = false
 * body = false
 * sites = all
 */
std::vector<MatchReturn> blacklisted_username(Post p) {
    std::vector<MatchReturn> ret;
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));

    if (p.username.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.username, m, all_lists.r_blacklisted_usernames)) 
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m));
    return ret;
}

/*
 * bad keyword in %s
 *
 * username = true
 * max_rep = 4
 * max_score = 1
 * sites = all
 */
std::vector<MatchReturn> bad_keyword(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o (false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;

    bool is_a = is_answer(p);
    if (!is_a) 
        if (boost::regex_search(p.title, m, all_lists.r_bad_keywords))
            ret[0] = MatchReturn(true, "bad keyword in title", "Title - " + get_position(m));
    if (!p.body.empty()) 
        if (boost::regex_search(p.body, m, all_lists.r_bad_keywords)) {
            ret[1] = MatchReturn(true, "bad keyword in body", "Body - " + get_position(m));
            if (is_a) ret[1].reason = "bad keyword in answer";
        }
    if (!p.username.empty())
        if (boost::regex_search(p.username, m, all_lists.r_bad_keywords))
            ret[2] = MatchReturn(true, "bad keyword in username", "Username - " + get_position(m));
    return ret;
}

/* Bad keyword extensions */

/* Filters yet to be implemented (probably incomplete list)
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L658-L676 
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L680-L710
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L749
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L752-L773
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L776-L785
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L808-L838
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L947-L969
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L972-L994
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L998-L1073
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1091-L1129
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1132-L1146
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1163-L1202
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1230-L1240
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1243-L1262
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1438-L1457
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1460-L1484
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1545-L1582
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1585-L1605
 * _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1622-L1661
 * _TODO: (some of these have not been implemented) https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L1622-L1661
 */

/* 
 * potentially bad keyword in %s
 *
 * username = true
 * max_rep = 30
 * max_score = 1
 * sites = all
 */
std::vector<MatchReturn> potentially_bad_keyword(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o (false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;

    bool is_a = is_answer(p);
    if (!is_a) 
        if (boost::regex_search(p.title, m, all_lists.r_watched_keywords))
            ret[0] = MatchReturn(true, "potentially bad keyword in title", "Title - " + get_position(m));
    if (!p.body.empty()) 
        if (boost::regex_search(p.body, m, all_lists.r_watched_keywords)) {
            ret[1] = MatchReturn(true, "potenitally bad keyword in body", "Body - " + get_position(m));
            if (is_a) ret[1].reason = "potentially bad keyword in answer";
        }
    if (!p.username.empty())
        if (boost::regex_search(p.username, m, all_lists.r_watched_keywords))
            ret[2] = MatchReturn(true, "potentially bad keyword in username", "Username - " + get_position(m));
    return ret;
}

/* 
 * blacklisted website in %s
 *
 * max_rep = 50
 * max_score = 5
 * sites = all
 */
std::vector<MatchReturn> blacklisted_website(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o (false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;

    bool is_a = is_answer(p);
    if (!is_a) 
        if (boost::regex_search(p.title, m, all_lists.r_blacklisted_websites))
            ret[0] = MatchReturn(true, "blacklisted website in title", "Title - " + get_position(m));
    if (!p.body.empty()) 
        if (boost::regex_search(p.body, m, all_lists.r_blacklisted_websites)) {
            ret[1] = MatchReturn(true, "blacklisted website in body", "Body - " + get_position(m));
            if (is_a) ret[1].reason = "blacklisted website in answer";
        }
    return ret;
}

/* 
 * repeated URL at end of long post
 *
 * title = false
 * stripcodeblocks = true
 * sites = all
 */
std::vector<MatchReturn> repeated_url(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (p.body.empty()) return ret;

    if (boost::regex_search(p.body, m, repeated_url_r))
        ret[1] = MatchReturn(true, "repeated URL at end of long post", "Body - " + get_position(m));
    return ret;
}

/* 
 * URL in title
 *
 * body = false
 * question-only = true
 * max_rep = 11
 * exempt-sites = stackoverflow.com, pt.stackoverflow.com, ru.stackoverflow.com, es.stackoverflow.com
 *                ja.stackoverflow.com, superuser.com, askubuntu.com, serverfault.com
 *                unix.stackexchange.com, webmaster.stackexchange.com
 */
std::vector<MatchReturn> url_in_title(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.title.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.title, m, url_in_title_r))
        ret[0] = MatchReturn(true, "URL in title", "Title - " + get_position(m));
    return ret;
}

/*
 * URL-only title (for the sites exempt above)
 *
 * body = false
 * question-only = true
 * max_rep = 11
 * sites = stackoverflow.com, pt.stackoverflow.com, ru.stackoverflow.com, es.stackoverflow.com
 *         ja.stackoverflow.com, superuser.com, askubuntu.com, serverfault.com
 *         unix.stackexchange.com, webmaster.stackexchange.com
 */
std::vector<MatchReturn> url_only_title(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.title.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.title, m, url_only_title_r))
        ret[0] = MatchReturn(true, "URL-only title", "Title - " + get_position(m));
    return ret;
}

/*
 * offensive %s detected
 *
 * max_rep = 101
 * max_score = 2
 * stripcodeblocks = true
 * sites = all
 */
std::vector<MatchReturn> offensive_post_detected(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    bool is_a = is_answer(p);
    std::vector<boost::smatch> matches;
    
    if (!is_a) {
        bool match = false;
        boost::smatch m;
        matches.clear();
        std::string s = p.title;
        int match_len = 0;
        std::string::const_iterator title_start(s.cbegin());
        while (boost::regex_search(title_start, s.cend(), m, offensive_post_r)) {
            match = true;
            matches.push_back(m);
            match_len += m[0].length();
            title_start = m.suffix().first;
        }
        /* currently at 1.5%, this can change if it needs to */
        if (match && (((float)match_len / (float)p.title.length()) >= 0.015))
            ret[0] = MatchReturn(true, "offensive title detected", "Title - " + get_positions(matches));
    }
    if (!p.body.empty()) {
        bool match = false;
        boost::smatch m;
        matches.clear();
        std::string s = p.body;
        int match_len = 0;
        std::string::const_iterator body_start(s.cbegin());
        while (boost::regex_search(body_start, s.cend(), m, offensive_post_r)) {
            match = true;
            matches.push_back(m);
            match_len += m[0].length();
            body_start = m.suffix().first;
        }
        /* currently at 1.5%, this can change if it needs to */
        if (match && (((float)match_len / (float)p.body.length()) >= 0.015)) {
            ret[1] = MatchReturn(true, "offensive body detected", "Body - " + get_positions(matches));
            if (is_a)
                ret[1].reason = "offensive answer detected";
        }
    }
    return ret;
}

/*
 * pattern-matching website in %s
 *
 * stripcodeblocks = true
 * max_score = 1
 * sites = all
 */
std::vector<MatchReturn> pattern_matching_website(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty()) 
        if (boost::regex_search(p.title, m, pattern_websites_r))
            ret[0] = MatchReturn(true, "pattern-matching website in title", "Title - " + get_position(m));
    if (!p.body.empty())
        if (boost::regex_search(p.body, m, pattern_websites_r)) {
            ret[1] = MatchReturn(true, "pattern-matching website in body", "Body - " + get_position(m));
            if (is_answer(p)) 
                ret[1].reason = "pattern-matching website in answer";
        }
    return ret;
}

/* Pattern-matching website extensions */

/* 
 * pattern-matching website extension 1
 * Country-name domains, travel and expats sites are exempt
 *
 * username = true
 * exempt-sites = travel.stackexchange.com, expatriates.stackexchange.com
 */
std::vector<MatchReturn> ext_1_pattern_matching_website(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, pattern_websites_ext_1_r))
        ret[0] = MatchReturn(true, "pattern-matching website in title", "Title - " + get_position(m));
    if (!p.body.empty() && boost::regex_search(p.body, m, pattern_websites_ext_1_r))
        ret[1] = MatchReturn(true, "pattern-matching website in body", "Body - " + get_position(m));
        if (is_answer(p))
            ret[1].reason = "pattern-matching website in answer";
    if (!p.username.empty() && boost::regex_search(p.username, m, pattern_websites_ext_1_r))
        ret[2] = MatchReturn(true, "pattern-matching website in username", "Username - " + get_position(m));
    return ret;
}

/*
 * pattern-matching website extension 2
 * The TLDs of Iran, Pakistan, and Tokelau in answers
 *
 * username = true
 * answer-only = true
 * sites = all
 */
std::vector<MatchReturn> ext_2_pattern_matching_website(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (!is_answer(p)) return ret;

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, pattern_websites_ext_2_r))
        ret[0] = MatchReturn(true, "pattern-matching website in title", "Title - " + get_position(m));
    if (!p.body.empty() && boost::regex_search(p.body, m, pattern_websites_ext_2_r)) {
        ret[1] = MatchReturn(true, "pattern-matching website in body", "Body - " + get_position(m));
        if (is_answer(p))
            ret[1].reason = "pattern-matching website in answer";
    }
    if (!p.username.empty() && boost::regex_search(p.username, m, pattern_websites_ext_2_r))
        ret[2] = MatchReturn(true, "pattern-matching website in username", "Username - " + get_position(m));
    return ret;
}

/*
 * pattern-matching website extension 3
 * Suspicious health-related websites, health sites are exempt
 *
 * username = true
 * max_rep = 4
 * max_score = 2
 * exempt-sites = fitness.stackexchange.com, biology.stackexchange.com, medicalsciences.stackexchange.com,
 *                skeptics.stackexchange.com, bicycles.stackexchange.com
 */
std::vector<MatchReturn> ext_3_pattern_matching_website(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, pattern_websites_ext_3_r))
        ret[0] = MatchReturn(true, "pattern-matching website in title", "Title - " + get_position(m));
    if (!p.body.empty() && boost::regex_search(p.body, m, pattern_websites_ext_3_r))
        ret[1] = MatchReturn(true, "pattern-matching website in body", "Body - " + get_position(m));
        if (is_answer(p))
            ret[1].reason = "pattern-matching website in answer";
    if (!p.username.empty() && boost::regex_search(p.username, m, pattern_websites_ext_3_r))
        ret[2] = MatchReturn(true, "pattern-matching website in username", "Username - " + get_position(m));
    return ret;
}

/* End of pattern-matching website extensions */

/*
 * bad pattern in URL %s
 *
 * sites = all
 * title = false
 * stripcodeblocks = true
 */
/* _TODO: Fix the regex in this filter */
/*
std::vector<MatchReturn> bad_pattern_in_url(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;

    std::vector<boost::smatch> matches;
    bool match = false;
    boost::smatch m;
    std::string s = p.body;
    
    std::string::const_iterator body_start(s.cbegin());
    while (boost::regex_search(body_start, s.cend(), m, bad_url_pattern_r)) {
        std::string temp(m[0]);
        if (boost::regex_match(temp, se_sites_url_re)) continue;
        match = true;
        matches.push_back(m);
        body_start = m.suffix().first;
    }
    ret[1] = MatchReturn(true, "bad pattern in url body", "Bad fragment in link - " 
            + get_positions(matches));
    if (is_answer(p)) ret[1].reason = "bad pattern in url answer";
    return ret;
}*/

/*
 * bad keyword with a link in %s
 *
 * title = false
 * answer-only = true
 * sites = all
 */
std::vector<MatchReturn> bad_keyword_with_link(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;
    if (p.body.length() > 400) return ret;

    std::string link;
    boost::smatch m;
    if (boost::regex_search(p.body, m, url_re)) {
        link = m[0];
        if (is_whitelisted_website(link)) return ret;
    } else 
        return ret;

    if (boost::regex_search(p.body, m, keyword_with_link_r)) {
        ret[1] = MatchReturn(true, "bad keyword with a link in answer",
                fmt::sprintf("Keyword *%s* with link %s", m[0], link));
        return ret;
    }

    std::string thanks_keyword;
    if (boost::regex_search(p.body, m, thanks_r)) 
        thanks_keyword = m[0];
    else 
        return ret;
    if (boost::regex_search(p.body, m, praise_r))
        ret[1] = MatchReturn(true, "bad keyword with a link in answer",
                fmt::sprintf("Keywords *%s*, *%s* with link %s", m[0], thanks_keyword, link));
    return ret;
}
    

/*
 * email in answer
 *
 * answer-only = true
 * stripcodeblocks = true
 * sites = biology.stackexchange.com, bitcoin.stackexchange.com, ell.stackexchange.com
 *         english.stackexchange.com, expatriates.stackexchange.com, gaming.stackexchange.com
 *         medicalsciences.stackexchange.com, money.stackexchange.com, parenting.stackexchange.com
 *         rpg.stackexchange.com, scifi.stackexchange.com, travel.stackexchange.com
 *         worldbuilding.stackexchange.com
 */
std::vector<MatchReturn> email_in_answer(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.body, m, email_in_answer_r))
        ret[0] = MatchReturn(true, "email in answer", "Body - " + get_position(m));
    return ret;
}

/*
 * email in %s
 *
 * question-only = true
 * stripcodeblocks = true
 * sites = biology.stackexchange.com, bitcoin.stackexchange.com, ell.stackexchange.com
 *         english.stackexchange.com, expatriates.stackexchange.com, gaming.stackexchange.com
 *         medicalsciences.stackexchange.com, money.stackexchange.com, parenting.stackexchange.com
 *         rpg.stackexchange.com, scifi.stackexchange.com, travel.stackexchange.com
 *         worldbuilding.stackexchange.com
 */
std::vector<MatchReturn> email_in_question(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.body.empty() && boost::regex_search(p.body, m, email_in_question_r))
        ret[1] = MatchReturn(true, "email in body", "Body - " + get_position(m));
    return ret;
}

/*
 * linked punctuation in %s
 *
 * title = false
 * stripcodeblocks = true
 * max_rep = 11
 * max_score = 1
 * answer-only = true
 * exempt-sites = codegolf.stackexchange.com
 */
std::vector<MatchReturn> linked_punctuation(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;
    if (!is_answer(p)) return ret;

    boost::smatch m;
    if (boost::regex_search(p.body, m, linked_punctuation_r))
        ret[1] = MatchReturn(true, "linked punctuation in answer", "Body - " + get_position(m));
    return ret;
}

/*
 * link following arrow in %s
 * Links preceded by arrows >>>
 *
 * question-only = true
 * max_rep = 11
 * sites = all
 */
std::vector<MatchReturn> link_following_arrow(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, link_following_arrow_r)) 
        ret[0] = MatchReturn(true, "link following arrow in title", "Title - " + get_position(m));
    if (!p.body.empty() && boost::regex_search(p.body, m, link_following_arrow_r))
        ret[1] = MatchReturn(true, "link following arrow in body", "Body - " + get_position(m));
    return ret;
}

/* 
 * link at end of %s
 * link at end of question, on selected sites
 *
 * title = false
 * sites = SuperUser, AskUbuntu, Drupal SE, MSE, Security SE, Patenta SE, Money SE, Gaming SE, 
 *         Arduino SE, Workplace
 */
/* _TODO: Move the regex out of this method to regex.cpp */
std::vector<MatchReturn> link_at_end_1(Post p) {
    std::vector<MatchReturn> ret;
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));

    boost::regex e1 ("</?(?:strong|em|p)>");
    p.body = boost::regex_replace(p.body, e1, "");
    boost::regex e ("(?i)https?://(?:[.A-Za-z0-9-]*/?[.A-Za-z0-9-]*/?|plus\\.google\\.com/[\\w/]*|www\\.pinterest\\.com/pin/[\\d/]*)(?=</a>\\s*$)");
   
    boost::smatch m;
    bool exists = boost::regex_search(p.body, m, e);
    bool is_a = is_answer(p);
    if (exists && !is_whitelisted_website(m[0])) {
        ret[1] = MatchReturn(true, "link at end of body", fmt::sprintf("Body - link at end: %s", get_position(m)));
        if (is_a) {
            ret[1].reason = "link at end of answer";
        }
    }
    return ret;
}

/*
 * link at end of %s
 * Link at the end of a short answer
 *
 * title = false
 * answer-only = true
 * exempt-sites = raspberrypi.stackexchange.com, softwarerecs.stackexchange.com
 */
std::vector<MatchReturn> link_at_end_2(Post p) {
    MatchReturn o(false, "", "");
    std::vector<MatchReturn> ret(3, o);

    if (!is_answer(p)) return ret;

    boost::smatch m;
    if (!p.body.empty() && boost::regex_search(p.body, m, link_at_end_2_r))
        ret[1] = MatchReturn(true, "link at end of answer", "Body - " + get_position(m));
    return ret;
}

/*
 * link at end of %s
 * Non-linked site at the end of a short answer
 *
 * title = false
 * answer-only = true
 * sites = all
 */
std::vector<MatchReturn> link_at_end_3(Post p) {
    MatchReturn o(false, "", "");
    std::vector<MatchReturn> ret(3, o);

    if (!is_answer(p)) return ret;

    boost::smatch m;
    if (!p.body.empty() && boost::regex_search(p.body, m, link_at_end_3_r)) 
        ret[1] = MatchReturn(true, "link at end of answer", "Body - " + get_position(m));
    return ret;
}

/*
 * shortened URL in body
 * Shortened URL near the end of a question
 *
 * title = false
 * question-only = true
 * exempt-sites = superuser.com, askubuntu.com
 */
std::vector<MatchReturn> shortened_url_question(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));

    if (is_answer(p)) return ret;

    boost::smatch m;
    if (!p.body.empty() && boost::regex_search(p.body, m, shortened_url_question_r))
        ret[1] = MatchReturn(true, "shortened URL in body", "Body - " + get_position(m));
    return ret;
}

/*
 * shortened URL in answer
 * Shortened URL in an answer
 *
 * stripcodeblocks = true
 * answer-only = true
 * exempt-sites = codegolf.stackexchange.com
 */
std::vector<MatchReturn> shortened_url_answer(Post p) {
    std::vector<MatchReturn> ret(3, MatchReturn(false, "", ""));

    if (!is_answer(p)) return ret;

    boost::smatch m;
    if (!p.body.empty() && boost::regex_search(p.body, m, shortened_url_answer_r))
        ret[1] = MatchReturn(true, "shortened URL in answer", "Body - " + get_position(m));
    return ret;
}

/*
 * no whitespace in %s
 *
 * max_rep = 10000
 * max_score = 10000
 * sites = all
 */
std::vector<MatchReturn> no_whitespace(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    bool is_a = is_answer(p);
    if (!is_a && boost::regex_search(p.title, m, title_whitespace_r)) 
        ret[0] = MatchReturn(true, "no whitespace in title", "no whitespace or formatting in title");
    if (boost::regex_search(p.body, m, body_whitespace_r)) {
        ret[1] = MatchReturn(true, "no whitespace in body", "no whitespace or formatting in body");
        if (is_a) {
            ret[1].reason = "no whitespace in answer";
        }
    }
    return ret;
}

/*
 * messaging number is %s
 *
 * stripcodeblocks = true
 * sites = all
 *
 * Checks for QQ/ICQ/WhatsApp numbers 
 */
std::vector<MatchReturn> messaging_number_detected(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    bool is_a = is_answer(p);
    if (!is_a && boost::regex_search(p.title, m, messaging_number_r)) 
        ret[0] = MatchReturn(true, "messaging number in title", "Title - " + get_position(m));
    if (boost::regex_search(p.body, m, messaging_number_r)) {
        ret[1] = MatchReturn(true, "messaging number in body", "Body - " + get_position(m));
        if (is_a)
            ret[1].reason = "messaging number in answer";
    }
    return ret;
}

/*
 * numbers-only title
 *
 * body = false
 * max_rep = 50
 * max_score = 5
 * excluding_sites = math.stackexchange.com
 * question-only = true
 */
std::vector<MatchReturn> numbers_only_title(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.title.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.title, m, number_only_r)) 
        ret[0] = MatchReturn(true, "numbers-only title", "Title - " + get_position(m));
    return ret;
}

/*
 * Title has only one unique char
 *
 * body = false
 * max_rep = 1000000
 * max_score = 10000
 * question-only = true
 * sites = all
 */
std::vector<MatchReturn> one_unique_char_in_title(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.title.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.title, m, one_unique_char_r)) 
        ret[0] = MatchReturn(true, "Title has only one unique char", "Title - " + get_position(m));
    return ret;
}

/*
 * Link inside deeply nested blockquotes
 *
 * sites = all
 * title = false
 * stripcodeblocks = true
 */
std::vector<MatchReturn> link_inside_nested_blockquotes(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.body, m, link_in_nested_blockquotes_r)) 
        ret[1] = MatchReturn(true, "Link inside deeply nested blockquotes", "Body - " + get_position(m));
    return ret;
}

/*
 * title ends with comma (IPS Troll)
 *
 * sites = interpersonal.stackexchange.com
 * body = false
 * max_rep = 50
 * question-only = true
 */
std::vector<MatchReturn> comma_at_title_end(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, comma_at_end_r))
        ret[0] = MatchReturn(true, "title ends with comma", "Title - " + get_position(m));
    return ret;
}

/*
 * title starts and ends with a forward slash
 *
 * sites = all
 * body = false
 * question-only = true
 */
std::vector<MatchReturn> title_starts_and_ends_with_slash(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    boost::smatch m;
    if (!p.title.empty() && boost::regex_search(p.title, m, title_slash_r)) {
        ret[0] = MatchReturn(true, "title starts and ends with a forward slash", "Title - " + 
                get_position(m));
    }
    return ret;
}

/* Some exceptional cases, for specific trolls */

/* 
 * Exceptional Blacklisted Username 1
 *
 * sites = drupal.stackexchange.com
 * title = false
 * body = false
 * username = true
 */
std::vector<MatchReturn> exc_blacklisted_username_1(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.username.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.username, m, exc_bad_username_1_r))
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m));
    return ret;
}

/* 
 * Exceptional Blacklisted Username 2
 *
 * sites = parenting.stackexchange.com
 * title = false
 * body = false
 * username = true
 */
std::vector<MatchReturn> exc_blacklisted_username_2(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.username.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.username, m, exc_bad_username_2_r))
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m));
    return ret;
}

/*
 * Exceptional Blacklisted Username 3
 *
 * sites = judaism.stackexchange.com
 * title = false
 * body = false
 * username = true
 */
std::vector<MatchReturn> exc_blacklisted_username_3(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.username.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.username, m, exc_bad_username_3_r))
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m));
    return ret;
}

/*
 * Exceptional Blacklisted Username 4
 * Judaism etc troll, 2018-04-18 (see also disabled watch above)
 *
 * sites = hinduism.stackexchang.com, judaism.stackexchange.com, islam.stackexchange.com
 * title = false
 * body = false
 * username = true
 */
std::vector<MatchReturn> exc_blacklisted_username_4(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.username.empty()) return ret;

    boost::smatch m;
    if (boost::regex_search(p.username, m, exc_bad_username_4_r))
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m));
    return ret;
}

