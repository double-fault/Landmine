/*
 * regex.h
 * Landmine
 *
 * Created by Ashish Ahuja on 10th February 2019.
 *
 *
*/

#ifndef Regex_h
#define Regex_h

#include <string.h>

#include <boost/regex.hpp>

#include <fmt/printf.h>
#include <fmt/format.h>
#include <fmt/core.h>

#include "lists.h"

extern Lists all_lists;

extern const boost::regex code_sub_1;
extern const boost::regex code_sub_2;

extern const boost::regex linked_punctuation_r;
extern const boost::regex title_whitespace_r;
extern const boost::regex body_whitespace_r;
extern const boost::regex messaging_number_r;
extern const boost::regex number_only_r;
extern const boost::regex one_unique_char_r;
extern const boost::regex link_in_nested_blockquotes_r;
extern const boost::regex comma_at_end_r;
extern const boost::regex title_slash_r;
extern const boost::regex exc_bad_username_1_r;
extern const boost::regex exc_bad_username_2_r;
extern const boost::regex exc_bad_username_3_r;
extern const boost::regex exc_bad_username_4_r;
extern const boost::regex repeated_url_r;
extern const boost::regex url_in_title_r;
extern const boost::regex url_only_title_r;
extern const boost::regex email_in_answer_r;
extern const boost::regex email_in_question_r;
extern const boost::regex one_character_link_r;
extern const boost::regex offensive_post_r;
extern const boost::regex bad_url_pattern_r;
extern const boost::regex praise_r;
extern const boost::regex thanks_r;
extern const boost::regex keyword_with_link_r;
extern const boost::regex link_following_arrow_r;
extern const boost::regex link_at_end_2_r;
extern const boost::regex link_at_end_3_r;
extern const boost::regex shortened_url_question_r;
extern const boost::regex shortened_url_answer_r;
extern const boost::regex word_chars_r;
extern const boost::regex non_latin_r;

extern const boost::regex se_sites_re;
extern const boost::regex se_sites_url_re;
extern const boost::regex whitelisted_websites_regex;
extern const boost::regex url_re;
extern const boost::regex link_re;
extern const boost::regex all_but_digits_re;

extern std::vector<std::string> se_sites_domains;
extern std::vector<std::string> pattern_websites;

extern const boost::regex pattern_websites_r;
extern const boost::regex pattern_websites_ext_1_r;
extern const boost::regex pattern_websites_ext_2_r;
extern const boost::regex pattern_websites_ext_3_r;

#endif /* Regex_h */

