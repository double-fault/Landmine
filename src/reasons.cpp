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
#include <boost/regex.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

/* Faup */
#include <faup/faup.h>
#include <faup/decode.h>
#include <faup/options.h>
#include <faup/output.h>

#include "post.h"
#include "findspam.h"

#define LEVEN_DOMAIN_DISTANCE 3

/* _TODO: Create a global Lists object and add it to the to-be-created header file.
 *        Name the Lists object `all_lists`
 */

/* _TODO: move these regexes to a separate global header file */

/* Regexes for specific reasons */
boost::regex title_whitespace_r ("(?is)^[0-9a-z]{20,}\s*$");
boost::regex body_whitespace_r ("(?is)^<p>[0-9a-z]+</p>\s*$");
boost::regex messaging_number_r ("(?i)(?<![a-z0-9])QQ?(?:(?:\w*[vw]x?|[^a-z0-9])\D{0,8})?\d{5}[.-]?"
        "\d{4,5}(?![\"\d])|\bICQ[ :]{0,5}\d{9}\b|\bwh?atsa+pp?[ :+]{0,5}\d{10}");
boost::regex number_only_r ("^(?=.*[0-9])[^\pL]*$");
boost::regex one_unique_char_r ("^(.)\1+$");
boost::regex link_in_nested_blockquotes_r ("(?:<blockquote>\s*){3,}<p><a href=\"([^<>]+)\"[^<>]*>\1</a>\s*</p>\s*</blockquote>");
boost::regex comma_at_end_r (".*\,$");
boost::regex title_slash_r ("^\/.*\/$");
boost::regex exc_bad_username_1_r ("^[A-Z][a-z]{3,7}(19\d{2})$");
boost::regex exc_bad_username_2_r ("(?i)^jeff$");
boost::regex exc_bad_username_3_r ("(?i)^keshav$");
boost::regex exc_bad_username_4_r ("(?i)^john$");
boost::regex repeated_url_r ("(?s)<a href=\"(?:http://%20)?(https?://(?:(?:www\.)?"
        "[\w-]+\.(?:blogspot\.|wordpress\.|co\.)?\w{2,10}/?"
        "[\w-]{0,40}?/?|(?:plus\.google|www\.facebook)\.com/[\w/]+))"
		"\" rel=\"nofollow( noreferrer)?\">"
		"(?="
		".{300,}<a href=\"(?:http://%20)?\1\" "
		"rel=\"nofollow( noreferrer)?\">(?:http://%20)?\1</a><Paste>"
        "(?:</strong>)?\W*</p>\s*$"
        ")");
boost::regex url_in_title_r ("(?i)https?://(?!(www\.)?(example|domain)\.(com|net|org))[a-zA-Z0-9_.-]+\.[a"
        "-zA-Z]{2,4}|\w{3,}\.(com|net)\b.*\w{3,}\.(com|net)\b");
boost::regex url_only_title_r ("(?i)^https?://(?!(www\.)?(example|domain)\.(com|net|org))"
        "[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,4}(/\S*)?$");
boost::regex email_in_answer_r ("(?i)(?<![=#/])\b[A-z0-9_.%+-]+@(?!(example|domain|site|foo|\dx)\.[A-z]" 
        "{2,4})[A-z0-9_.%+-]+\.[A-z]{2,4}\b");
boost::regex email_in_question_r ("(?i)(?<![=#/])\b[A-z0-9_.%+-]+@(?!(example|domain|site|foo|\dx)\.[A-z]"
        "{2,4})[A-z0-9_.%+-]+\.[A-z]{2,4}\b(?s)(?=.{,100}$)");
boost::regex one_character_link_r ("(?iu)\w<a href=\"[^\"]+\" rel=\"nofollow( noreferrer)?\">.</a>\w");
boost::regex offensive_post_r (
        "(?is)\b((?:ur\Wm[ou]m|(yo)?u suck|[8B]={3,}[D>)]\s*[.~]*|nigg[aeu][rh]?|(ass\W?|a|a-)hole|"
        "daf[au][qk]|(?<!brain)(mother|mutha)?f\W*u\W*c?\W*k+(a|ing?|e?[rd]| *off+| *(you|ye|u)(rself)?|"
        " u+|tard)?|(bul+)?shit(t?er|head)?|(yo)?u(r|'?re)? (gay|scum)|dickhead|(?:fur)?fa+g+(?:ot)?s?\b|"
        "pedo(?!bapt|dont|log|mete?r|troph)|cocksuck(e?[rd])?|"
        "whore|cunt|jerk(ing)?\W?off|cumm(y|ie)|butthurt|queef|lesbo|"
        "bitche?|(eat|suck|throbbing|sw[oe]ll(en|ing)?)\b.{0,20}\b(cock|dick)|dee[sz]e? nut[sz]|"
        "dumb\W?ass|wet\W?puss(y|ie)?|slut+y?|shot\W?my\W?(hot\W?)?load)s?)\b");
boost::regex bad_url_pattern_r (
        "<a href=\"(?P<frag>[^\"]*-reviews?(?:-(?:canada|(?:and|or)-scam))?/?|[^\"]*-support/?)\"|" 
        "<a href=\"[^\"]*\"(?:\\s+\"[^\"]*\")*>(?P<frag>[^\"]" 
        "*-reviews?(?:-(?:canada|(?:and|or)-scam))?/?|[^\"]*-support/?)</a>");
boost::regex praise_r(
        "(?i)\b(nice|good|interesting|helpful|great|amazing) (article|blog|post|information)\b|"
        "very useful");
boost::regex thanks_r("(?i)\b(appreciate|than(k|ks|x))\b");
boost::regex keyword_with_link_r(
        "(?i)\b(I really appreciate|many thanks|thanks a lot|thank you (very|for)|"
        "than(ks|x) for (sharing|this|your)|dear forum members|(very (informative|useful)|"
        "stumbled upon (your|this)|wonderful|visit my) (blog|site|website))\b");
boost::regex link_following_arrow_r(
        "(?is)(?:>>+|[@:]+>+|==\s*>+|={4,}|===>+|= = =|Read More|Click Here).{,20}"
        "https?://(?!i\.stack\.imgur\.com)(?=.{,200}$)");
boost::regex link_at_end_2_r(
        "(?is)(?<=^.{,350})<a href=\"https?://(?:(?:www\.)?[\w-]+\.(?:blogspot\.|wordpress\.|co\.)?\w{2,4}"
        "/?\w{0,2}/?|(?:plus\.google|www\.facebook)\.com/[\w/]+)\"[^<]*</a>(?:</strong>)?\W*</p>\s*$"
        "|\[/url\]\W*</p>\s*$");
boost::regex link_at_end_3_r("(?is)\w{3}(?<![/.]tcl)\.tk(?:</strong>)?\W*</p>\s*$");
boost::regex shortend_url_question_r(
        "(?is)://(?:w+\.)?(goo\.gl|bit\.ly|bit\.do|tinyurl\.com|fb\.me|cl\.ly|t\.co|is\.gd|j\.mp|tr\.im|"
        "wp\.me|alturl\.com|tiny\.cc|9nl\.me|post\.ly|dyo\.gs|bfy\.tw|amzn\.to|adf\.ly|adfoc\.us|"
        "surl\.cn\.com|clkmein\.com|bluenik\.com|rurl\.us|adyou\.co|buff\.ly|ow\.ly|tgig\.ir)/(?=.{,200}$)"
        );
boost::regex shortened_url_answer_r(
        "(?is)://(?:w+\.)?(goo\.gl|bit\.ly|bit\.do|tinyurl\.com|fb\.me|cl\.ly|t\.co|is\.gd|j\.mp|tr\.im|"
        "wp\.me|alturl\.com|tiny\.cc|9nl\.me|post\.ly|dyo\.gs|bfy\.tw|amzn\.to|adf\.ly|adfoc\.us|"
        "surl\.cn\.com|clkmein\.com|bluenik\.com|rurl\.us|adyou\.co|buff\.ly|ow\.ly)/");
boost::regex word_chars_r("(?u)[\W0-9]|http\S*");
boost::regex non_latin_r("(?u)\p{script=Latin}|\p{script=Cyrillic}");

/* General regexes and other things, used across multiple reasons */
std::string se_sites_s ("(?:(?:[a-z]+\\.)*stackoverflow\\.com|(?:askubuntu|superuser|serverfault" 
        "|stackapps|imgur)\\.com|mathoverflow\\.net|(?:[a-z]+\\.)*stackexchange\\.com)");
boost::regex se_sites_re(se_sites_s);
boost::regex se_sites_url_re(fmt::sprintf("^https?://%s", se_sites_s));
boost::regex whitelisted_websites_regex (
        "(?i)upload|\x08(?:yfrog|gfycat|tinypic|sendvid|ctrlv|prntscr|gyazo|youtu\\.?be|"
        "past[ie]|dropbox|microsoft|newegg|cnet|regex101|(?<!plus\\.)google|localhost|ubuntu|"
        "getbootstrap|jsfiddle\\.net|codepen\\.io|pastebin|stackoverflow\\.com|askubuntu\\.com"
        "|superuser\\.com|serverfault\\.com|mathoverflow\\.net|stackapps\\.com|stackexchange\\.com"
        "|sstatic\\.net|imgur\\.com)\x08");
boost::regex url_re ("(?i)<a href=\"https?://\S+");
boost::regex link_re("<a href=\"([^\"]+)\"[^>]*>([^<]+)<\/a>");
boost::regex all_but_digits_re("[^\d]");

std::vector<std::string> se_sites_domains = {
    "stackoverflow.com", "askubuntu.com", "superuser.com", "serverfault.com", "mathoverflow.net",
    "stackapps.com", "stackexchange.com", "sstatic.net", "imgur.com"};

/* Patterns: the top four lines are the most straightforward, matching any site with this string in domain name */
std::vector<std::string> pattern_websites = {
    "(enstella|recoverysoftware|removevirus|support(number|help|quickbooks)|techhelp|calltech|exclusive|"
    "onlineshop|video(course|classes|tutorial(?!s))|vipmodel|(?<!word)porn|wholesale|inboxmachine|(get|buy)cheap|"
    "escort|diploma|(govt|government)jobs|extramoney|earnathome|spell(caster|specialist)|profits|"
    "seo-?(tool|service|trick|market)|onsale|fat(burn|loss)|(\.|//|best)cheap|online-?(training|solution)"
    "|\bbabasupport\b|movieshook)"
    "[\w-]*\.(com?|net|org|in(\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\.)|info)",
    "(replica(?!t)|rs\d?gold|rssong|runescapegold|maxgain|e-cash|mothers?day|phone-?number|fullmovie|tvstream|"
    "trainingin|dissertation|(placement|research)-?(paper|statement|essay)|digitalmarketing|infocampus|freetrial|"
    "cracked\w{3}|bestmover|relocation|\w{4}mortgage|revenue|testo[-bsx]|cleanse|cleansing|detox|suppl[ei]ment|"
    "loan|herbal|serum|lift(eye|skin)|(skin|eye)lift|luma(genex|lift)|renuva|svelme|santeavis|wrinkle|topcare)"
    "[\w-]*\.(com?|net|org|in(\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\.)|info)",
    "(drivingschool|crack-?serial|serial-?(key|crack)|freecrack|appsfor(pc|mac)|probiotic|remedies|heathcare|"
    "sideeffect|meatspin|packers\S{0,3}movers|(buy|sell)\S{0,12}cvv|goatse|burnfat|gronkaffe|muskel|"
    "tes(tos)?terone|nitric(storm|oxide)|masculin|menhealth|intohealth|babaji|spellcaster|potentbody|slimbody|"
    "slimatrex|moist|lefair|derma(?![nt])|xtrm|factorx|(?<!app)nitro(?!us)|endorev|ketone)"
    "[\w-]*\.(com?|net|org|in(\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\.)|info)",
    "(moving|\w{10}spell|[\w-]{3}password|(?!greatfurniture)\w{5}deal|(?!nfood)\w{5}facts|\w\dfacts|\Btoyshop|"
    "[\w-]{5}cheats|"
    "(?!djangogirls\.org(?:$|[/?]))[\w-]{6}girls|"
    "clothing|shoes(inc)?|cheatcode|cracks|credits|-wallet|refunds|truo?ng|viet|"
    "trang)\.(co|net|org|in(\W|fo)|us)",
    "(health|earn|max|cash|wage|pay|pocket|cent|today)[\w-]{0,6}\d+\.com",
    "(//|www\.)healthy?\w{5,}\.com",
    "https?://[\w-.]\.repair\W", "https?://[\w-.]{10,}\.(top|help)\W",
    "filefix(er)?\.com", 
    "\.page\.tl\W", 
    "infotech\.(com|net|in)",
    "\.(com|net)/(xtra|muscle)[\w-]", 
    "http\S*?\Wfor-sale\W",
    "fifa\d+[\w-]*?\.com", 
    "[\w-](giveaway|jackets|supplys|male)\.com",
    "((essay|resume|click2)\w{6,}|(essays|(research|term)paper|examcollection|[\w-]{5}writing|"
    "writing[\w-]{5})[\w-]*?)\.(com?|net|org|in(\W|fo)|us|us)",
    "(top|best|expert)\d\w{0,15}\.in\W", 
    "\dth(\.co)?\.in", 
    "(jobs|in)\L<city>\.in",
    "[\w-](recovery|repairs?|rescuer|(?<!epoch|font)converter)(pro|kit)?\.(com|net)",
    "(corrupt|repair)[\w-]*?\.blogspot",
    "http\S*?(yahoo|gmail|hotmail|outlook|office|microsoft)?[\w-]{0,10}"
    "(account|tech|customer|support|service|phone|help)[\w-]{0,10}(service|"
    "care|help|recovery|support|phone|number)",
    "http\S*?(essay|resume|thesis|dissertation|paper)-?writing",
    "fix[\w-]*?(files?|tool(box)?)\.com", 
    "(repair|recovery|fix)tool(box)?\.(co|net|org)",
    "smart(pc)?fixer\.(co|net|org)",
    "password[\w-]*?(cracker|unlocker|reset|buster|master|remover)\.(co|net)",
    "crack[\w-]*?(serial|soft|password)[\w-]*?\.(co|net)",
    "(downloader|pdf)converter\.(com|net)",
    "ware[\w-]*?download\.(com|net|info|in\W)",
    "((\d|\w{3})livestream|livestream(ing|s))[\w]*?\.(com|net|tv)", 
    "\w+vs\w+live\.(com|net|tv)",
    "(play|watch|cup|20)[\w-]*?(live|online)\.(com|net|tv)", 
    "worldcup\d[\w-]*?\.(com|net|tv|blogspot)",
    "https?://(\w{5,}tutoring\w*|cheat[\w-.]{3,}|xtreme[\w-]{5,})\.",
    "(platinum|paying|acai|buy|premium|premier|ultra|thebest|best|[/.]try)[\w]{10,}\.(co|net|org|in(\W|fo)|us)",
    "(training|institute|marketing)[\w-]{6,}[\w.-]*?\.(co|net|org|in(\W|fo)|us)",
    "[\w-](courses?|training)[\w-]*?\.in/",
    "\w{9}(buy|roofing)\.(co|net|org|in(\W|fo)|us)",
    /* (something)health.(something)*/
    "(vitamin|dive|hike|love|strong|ideal|natural|pro|magic|beware|top|best|free|cheap|allied|nutrition|"
    "prostate)[\w-]*?health[\w-]*?\.(co|net|org|in(\W|fo)|us|wordpress|blogspot|tumblr|webs\.)",
    /* (something)cream.(something) */
    "(eye|skin|age|aging)[\w-]*?cream[\w-]*?\.(co|net|org|in(\W|fo)|us|wordpress|blogspot|tumblr|webs\.)",
    /* (keyword)(something)(keyword)(something).(something) */
    "(acai|advance|aging|alpha|beauty|belle|beta|biotic|body|boost(?! solution)|brain(?!tree)|burn|colon|"
    "[^s]cream|cr[eè]me|derma|ecig|eye|face(?!book)|fat|formula|geniu[sx]|grow|hair|health|herbal|ideal|luminous|"
    "male|medical|medicare|muscle|natura|no2|nutrition|optimal|pearl|perfect|phyto|probio|rejuven|revive|ripped|"
    "rx|scam|shred|skin|slim|super|testo|[/.]top|trim|[/.]try|ultra|ultra|vapor|vita|weight|wellness|xplode|yoga|"
    "young|youth)[\w]{0,20}(about|advi[sc]|assess|blog|brazil|canada|care|center|centre|chat|complex(?!ity)|"
    "congress|consult|critic|critique|cure|denmark|discussion|doctor|dose|essence|essential|extract|fact|formula|"
    "france|funct?ion|genix|guide|help|idea|info|jacked|l[iy]ft|mag|market|max|mexico|norway|nutrition|order|plus|"
    "points|policy|potency|power|practice|pro|program|report|review|rewind|site|slim|solution|suppl(y|ier)|sweden|"
    "tip|trial|try|world|zone)[.\w-]{0,12}\.(co|net|org|in(\W|fo)|us|wordpress|blogspot|tumblr|webs\.)",
    "(\w{11}(idea|income|sale)|\w{6}(<?!notebook)(advice|problog|review))s?\.(co|net|in(\W|fo)|us)",
    "-(poker|jobs)\.com", "send[\w-]*?india\.(co|net|org|in(\W|fo)|us)",
    "(file|photo|android|iphone)recovery[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "(videos?|movies?|watch)online[\w-]*?\.", "hd(video|movie)[\w-]*?\.",
    "backlink(?!(o\.|watch))[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "(replica[^nt]\w{5,}|\wrolex)\.(co|net|org|in(\W|fo)|us)",
    "customer(service|support)[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "conferences?alert[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "seo\.com(?!/\w)", 
    "\Wseo(?!sitecheckup)[\w-]{10,}\.(com|net|in\W)",
    "(?<!site)24x7[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "backlink[\w-]*?\.(com|net|de|blogspot)",
    "(software|developers|packers|movers|logistic|service)[\w-]*?india\.(com|in\W)",
    "scam[\w-]*?(book|alert|register|punch)[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "http\S*?crazy(mass|bulk)", 
    "http\S*\.com\.com[/\"<]",
    "https?://[^/\s]{8,}healer",
    "reddit\.com/\w{6}/\"",
    "world[\w-]*?cricket[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "(credit|online)[\w-]*?loan[\w-]*?\.(co|net|org|in(\W|fo)|us)",
    "worldcup\d+live\.(com?|net|org|in(\W|fo)|us)",
    "((concrete|beton)-?mixer|crusher)[\w-]*?\.(co|net)",
    "\w{7}formac\.(com|net|org)",
    "sex\.(com|net|info)", "https?://(www\.)?sex",
    "[\w-]{12}\.(webs|66ghz)\.com", 
    "online\.us[/\"<]",
    "ptvsports\d+.com",
    "youth\Wserum",
    "buyviewsutube",
    "(?:celebrity-?)?net-?worth", 
    "richestcelebrities",
    "ufc\wfight\wnight" /* Chiesa vs Lee spam */
}

boost::regex pattern_websites_r(fmt::sprintf("(?i)(%s|[\w-]*?(%s)[\w-]*?\.(com?|net|org|in(fo)?|us|blogspot|wordpress))(?![^>]*<)",
            join(pattern_websites, '|'), join(all_list.bad_keywords_nwb.elements, '|')));
boost::regex pattern_websites_ext_1_r(
        "(?i)\b(?:[\w-]{6,}|\w*shop\w*)(australia|brazil|canada|denmark|france|india|mexico|norway"
        "|pakistan|spain|sweden)\w{0,4}\.(com|net)");
boost::regex pattern_websites_ext_2_r("(?i)http\S*?(?<![/.]tcl)\.(ir|pk|tk)(?=[/\"<])");
boost::regex pattern_websites_ext_3_r(
        "(?i)(bodybuilding|workout|fitness(?!e)|diet|perfecthealth|muscle|nutrition(?!ix)|"
        "prostate)[\w-]*?\.(com|co\.|net|org|info|in\W)");

/* Utility functions */
/* _TODO: include these utility functions in the to-be-made header file as well */

bool is_answer(Post p) {
    if (p.title.end()) return true;
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

std::string join(std::vector<std::string> elements, char del) {
    std::string ret;
    for (auto &s:elements) ret += (s + del);
    ret.pop_back(); return ret;
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
 * priority = 1 (not experimental)
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
 */
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
}

/* Utility function for checking numbers.
 * Since this is pretty much a filter, it doesn't fall in the utilities section */
std::pair<bool, std::string> check_numbers(std::string s, std::set<std::string> numlist,
        std::set<std::string> numlist_normalized) {
    std::vector<std::string> matches; bool match = false;
    std::string::const_iterator s_iter(s.cbegin());
    std::smatch m;
    while (boost::regex_search(s_iter, s.cend(), m, all_lists.r_numbers)) {
        if (numlist.find(m[0]) != numlist.end()) {
            match = true; matches.push_back(fmt::sprintf("%s found verbatim.", m[0]));
            s_iter = m.suffix().first;
            continue;
        }
        std::string normalized_candidate = boost::regex_replace(m[0], all_but_digits_re, ""); 
        if (numlist_normalized.find(normalized_candidate) != numlist_normalized.end()) {
            match = true; matches.push_back(fmt::sprintf("%s found normalized.", normalized_candidate));
        }

        s_iter = m.suffix().first;
    }
    if (match) 
        return std::make_pair(true, join(matches, ';'));
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
 * phone number detected in title

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
        ret[2] = MatchReturn(true, "blacklisted username", "Username - " + get_position(m);
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
/* _TODO: https://github.com/Charcoal-SE/SmokeDetector/blob/master/findspam.py#L658-L676 
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
    if (!p.body.empty() && boost::regex_search(p.body, m, pattern_websites_ext_1_r)) {
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
    if (!p.body.empty() && boost::regex_search(p.body, m, pattern_websites_ext_3_r)) {
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
std::vector<MatchReturn> bad_pattern_in_url(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;

    std::vector<MatchReturn> matches;
    bool match = false;
    boost::smatch m;
    std::string s = p.body;
    
    std::string::const_iterator body_start(s.cbegin());
    while (boost::regex_search(body_start, s.cend(), m, bad_url_pattern_r)) {
        boost::smatch temp;
        if (boost::regex(m[0], temp, se_sites_url_re)) continue;
        match = true;
        matches.push_back(m);
        body_start = m.suffix().first;
    }
    ret[1] = MatchReturn(true, "bad pattern in url body", "Bad fragment in link - " 
            + get_positions(matches));
    if (is_answer(p)) ret[1].reason = "bad pattern in url answer";
    return ret;
}

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

    if (boost::regex_search(post["body"], m, keyword_with_link_r)) {
        ret[1] = MatchReturn(true, "bad keyword with a link in answer",
                fmt::sprintf("Keyword *%s* with link %s", m[0], link));
        return ret;
    }

    std::string thanks_keyword;
    if (boost::regex_search(post["body"], m, thanks_r)) 
        thanks_keyword = m[0];
    else 
        return ret;
    if (boost::regex_search(post["body"], m, praise_r))
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
    if (!p.title.empty() && boost::regex_search(p.title, m, email_in_question_r))
        ret[0] = MatchReturn(true, "email in title", "Title - " + get_position(m));
    if (!p.body.empty() && boost::regex_search(p.body, m, email_in_question_r))
        ret[1] = MatchReturn(true, "email in body", "Body - " + get_position(m));
    return ret;
}

/*
 * one-character link in %s
 *
 * title = false
 * stripcodeblocks = true
 * max_rep = 11
 * max_score = 1
 * sites = all
 */
std::vector<MatchReturn> one_character_link(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

    if (p.body.empty()) return ret;

    bool is_a = is_answer(p);

    boost::smatch m;
    if (boost::regex_search(p.body, m, one_character_link_r)) {
        ret[1] = MatchReturn(true, "one-character link in body", "body - " + get_position(m));
        if (is_a)
            ret[1].reason = "one-character link in answer";
    }
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
std::vector<MatchReturn> link_at_end_1(Post p) {
    std::vector<MatchReturn> ret;
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));
    ret.push_back(MatchReturn(false, "", ""));

    boost::regex e ("</?(?:strong|em|p)>");
    p.body = boost::regex_replace(p.body, e, "");
    boost::regex e = ("(?i)https?://(?:[.A-Za-z0-9-]*/?[.A-Za-z0-9-]*/?|plus\.google\.com/[\w/]*|www\.pinterest\.com/pin/[\d/]*)(?=</a>\s*$)");
   
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
    if (!p.body.empty() && boost::regex_search(p.body, m, shortend_url_question_r))
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
 * excluding_sites = Math SE
 * question-only = true
 */
std::vector<MatchReturn> numbers_only_title(Post p) {
    std::vector<MatchReturn> ret;
    MatchReturn o = MatchReturn(false, "", "");
    ret.push_back(o); ret.push_back(o); ret.push_back(o);

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

    boost::smatch m;
    if (boost::regex_search(p.title, m, one_unique_char)) 
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
    if (boost::regex_search(p.title, m, comma_at_end_r))
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
    if (boost::regex_search(p.title, m, title_slash_r)) {
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

