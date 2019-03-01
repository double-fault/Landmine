/*
 * reasons.h
 * Landmine
 *
 * Created by Ashish Ahuja on 25th January 2019.
 *
 *
*/

#ifndef Reasons_h
#define Reasons_h

#include <string>
#include <vector>

#include "post.h"
#include "findspam.h"

/* All reasons/rules/filters */
std::vector<MatchReturn> misleading_link(Post p);
std::vector<MatchReturn> mostly_non_latin(Post p);
std::vector<MatchReturn> bad_phone_number(Post p);
std::vector<MatchReturn> watched_phone_number(Post p);
std::vector<MatchReturn> blacklisted_username(Post p);
std::vector<MatchReturn> bad_keyword(Post p);
std::vector<MatchReturn> has_customer_service(Post p);
std::vector<MatchReturn> has_health(Post p);
std::vector<MatchReturn> potentially_bad_keyword(Post p);
std::vector<MatchReturn> blacklisted_website(Post p);
std::vector<MatchReturn> repeated_url(Post p);
std::vector<MatchReturn> url_in_title(Post p);
std::vector<MatchReturn> url_only_title(Post p);
std::vector<MatchReturn> offensive_post_detected(Post p);
std::vector<MatchReturn> pattern_matching_website(Post p);
std::vector<MatchReturn> ext_1_pattern_matching_website(Post p);
std::vector<MatchReturn> ext_3_pattern_matching_website(Post p);
std::vector<MatchReturn> ext_2_pattern_matching_website(Post p);
std::vector<MatchReturn> bad_pattern_in_url(Post p);
std::vector<MatchReturn> bad_keyword_with_link(Post p);
std::vector<MatchReturn> email_in_answer(Post p);
std::vector<MatchReturn> email_in_question(Post p);
std::vector<MatchReturn> linked_punctuation(Post p);
std::vector<MatchReturn> link_following_arrow(Post p);
std::vector<MatchReturn> link_at_end_1(Post p);
std::vector<MatchReturn> link_at_end_2(Post p);
std::vector<MatchReturn> link_at_end_3(Post p);
std::vector<MatchReturn> shortened_url_question(Post p);
std::vector<MatchReturn> shortened_url_answer(Post p);
std::vector<MatchReturn> no_whitespace(Post p);
std::vector<MatchReturn> messaging_number_detected(Post p);
std::vector<MatchReturn> numbers_only_title(Post p);
std::vector<MatchReturn> one_unique_char_in_title(Post p);
std::vector<MatchReturn> link_inside_nested_blockquotes(Post p);
std::vector<MatchReturn> comma_at_title_end(Post p);
std::vector<MatchReturn> title_starts_and_ends_with_slash(Post p);
std::vector<MatchReturn> exc_blacklisted_username_1(Post p);
std::vector<MatchReturn> exc_blacklisted_username_2(Post p);
std::vector<MatchReturn> exc_blacklisted_username_3(Post p);
std::vector<MatchReturn> exc_blacklisted_username_4(Post p);

#endif /* Reasons_h */

