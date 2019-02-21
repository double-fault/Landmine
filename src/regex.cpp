/*
 * regex.cpp
 * Landmine
 *
 * Created by Ashish Ahuja on 10th February 2019.
 *
 *
*/

#include <string.h>

#include <boost/regex.hpp>

#include <fmt/printf.h>
#include <fmt/format.h>
#include <fmt/core.h>

#include "utility.h"
#include "regex.h"
#include "lists.h"

Lists all_lists("landmine_data.json");

const boost::regex code_sub_1{"(?s)<pre>.*?</pre>"};
const boost::regex code_sub_2{"(?s)<code>.*?</code>"};

/* _TODO: move these regexes to a separate global header file */

/* Regexes for specific reasons */
/* _TODO: Add unicode support for linked_punctuation_r (?iu) */
const boost::regex linked_punctuation_r ("(?i)rel=\"nofollow( noreferrer)?\">(?!><>)\\W+</a>");
const boost::regex title_whitespace_r ("(?is)^[0-9a-z]{20,}\\s*$");
const boost::regex body_whitespace_r ("(?is)^<p>[0-9a-z]+</p>\\s*$");
const boost::regex messaging_number_r ("(?i)(?<![a-z0-9])QQ?(?:(?:\\w*[vw]x?|[^a-z0-9])\\D{0,8})?\\d{5}[.-]?"
        "\\d{4,5}(?![\"\\d])|\\bICQ[ :]{0,5}\\d{9}\\b|\\bwh?atsa+pp?[ :+]{0,5}\\d{10}");
const boost::regex number_only_r ("^(?=.*[0-9])[^\\pL]*$");
const boost::regex one_unique_char_r ("^(.)\\1+$");
const boost::regex link_in_nested_blockquotes_r ("(?:<blockquote>\\s*){3,}<p><a href=\"([^<>]+)\"[^<>]*>\\1</a>\\s*</p>\\s*</blockquote>");
const boost::regex comma_at_end_r (".*\\,$");
const boost::regex title_slash_r ("^\\/.*\\/$");
const boost::regex exc_bad_username_1_r ("^[A-Z][a-z]{3,7}(19\\d{2})$");
const boost::regex exc_bad_username_2_r ("(?i)^jeff$");
const boost::regex exc_bad_username_3_r ("(?i)^keshav$");
const boost::regex exc_bad_username_4_r ("(?i)^john$");
const boost::regex repeated_url_r ("(?s)<a href=\"(?:http://%20)?(https?://(?:(?:www\\.)?"
        "[\\w-]+\\.(?:blogspot\\.|wordpress\\.|co\\.)?\\w{2,10}/?"
        "[\\w-]{0,40}?/?|(?:plus\\.google|www\\.facebook)\\.com/[\\w/]+))"
                "\" rel=\"nofollow( noreferrer)?\">"
                "(?="
                ".{300,}<a href=\"(?:http://%20)?\\1\" "
                "rel=\"nofollow( noreferrer)?\">(?:http://%20)?\\1</a>"
        "(?:</strong>)?\\W*</p>\\s*$"
        ")");
const boost::regex url_in_title_r ("(?i)https?://(?!(www\\.)?(example|domain)\\.(com|net|org))[a-zA-Z0-9_.-]+\\.[a"
        "-zA-Z]{2,4}|\\w{3,}\\.(com|net)\\b.*\\w{3,}\\.(com|net)\\b");
const boost::regex url_only_title_r ("(?i)^https?://(?!(www\\.)?(example|domain)\\.(com|net|org))"
        "[a-zA-Z0-9_.-]+\\.[a-zA-Z]{2,4}(/\\S*)?$");
const boost::regex email_in_answer_r ("(?i)(?<![=#/])\\b[A-z0-9_.%+-]+@(?!(example|domain|site|foo|\\dx)\\.[A-z]"
        "{2,4})[A-z0-9_.%+-]+\\.[A-z]{2,4}\\b");
const boost::regex email_in_question_r ("(?is)(?<![=#/])\\b[A-z0-9_.%+-]+@(?!(example|domain|site|foo|\\dx)\\.[A-z]"
        "{2,4})[A-z0-9_.%+-]+\\.[A-z]{2,4}\\b(?=.{,100}$)");
const boost::regex offensive_post_r (
        "(?is)\\b((?:ur\\Wm[ou]m|(yo)?u suck|[8B]={3,}[D>)]\\s*[.~]*|nigg[aeu][rh]?|(ass\\W?|a|a-)hole|"
        "daf[au][qk]|(?<!brain)(mother|mutha)?f\\W*u\\W*c?\\W*k+(a|ing?|e?[rd]| *off+| *(you|ye|u)(rself)?|"
        " u+|tard)?|(bul+)?shit(t?er|head)?|(yo)?u(r|'?re)? (gay|scum)|dickhead|(?:fur)?fa+g+(?:ot)?s?\\b|"
        "pedo(?!bapt|dont|log|mete?r|troph)|cocksuck(e?[rd])?|"
        "whore|cunt|jerk(ing)?\\W?off|cumm(y|ie)|butthurt|queef|lesbo|"
        "bitche?|(eat|suck|throbbing|sw[oe]ll(en|ing)?)\\b.{0,20}\\b(cock|dick)|dee[sz]e? nut[sz]|"
        "dumb\\W?ass|wet\\W?puss(y|ie)?|slut+y?|shot\\W?my\\W?(hot\\W?)?load)s?)\\b");
/* _TODO: fix this */
/*
const boost::regex bad_url_pattern_r (
        "<a href=\"(?P<frag>[^\"]*-reviews?(?:-(?:canada|(?:and|or)-scam))?/?|[^\"]*-support/?)\"|" 
        "<a href=\"[^\"]*\"(?:\\s+\"[^\"]*\")*>(?P<frag>[^\"]" 
        "*-reviews?(?:-(?:canada|(?:and|or)-scam))?/?|[^\"]*-support/?)</a>");*/
const boost::regex praise_r(
        "(?i)\\b(nice|good|interesting|helpful|great|amazing) (article|blog|post|information)\\b|"
        "very useful");
const boost::regex thanks_r("(?i)\b(appreciate|than(k|ks|x))\\b");
const boost::regex keyword_with_link_r(
        "(?i)\\b(I really appreciate|many thanks|thanks a lot|thank you (very|for)|"
        "than(ks|x) for (sharing|this|your)|dear forum members|(very (informative|useful)|"
        "stumbled upon (your|this)|wonderful|visit my) (blog|site|website))\\b");
const boost::regex link_following_arrow_r(
        "(?is)(?:>>+|[@:]+>+|==\\s*>+|={4,}|===>+|= = =|Read More|Click Here).{,20}"
        "https?://(?!i\\.stack\\.imgur\\.com)(?=.{,200}$)");
const boost::regex link_at_end_2_r(
        "(?is)(?<=^.{,350})<a href=\"https?://(?:(?:www\\.)?[\\w-]+\\.(?:blogspot\\.|wordpress\\.|co\\.)?\\w{2,4}"
        "/?\\w{0,2}/?|(?:plus\\.google|www\\.facebook)\\.com/[\\w/]+)\"[^<]*</a>(?:</strong>)?\\W*</p>\\s*$"
        "|\\[/url\\]\\W*</p>\\s*$");
const boost::regex link_at_end_3_r("(?is)\\w{3}(?<![/.]tcl)\\.tk(?:</strong>)?\\W*</p>\\s*$");
const boost::regex shortened_url_question_r(
        "(?is)://(?:w+\\.)?(goo\\.gl|bit\\.ly|bit\\.do|tinyurl\\.com|fb\\.me|cl\\.ly|t\\.co|is\\.gd|j\\.mp|tr\\.im|"
        "wp\\.me|alturl\\.com|tiny\\.cc|9nl\\.me|post\\.ly|dyo\\.gs|bfy\\.tw|amzn\\.to|adf\\.ly|adfoc\\.us|"
        "surl\\.cn\\.com|clkmein\\.com|bluenik\\.com|rurl\\.us|adyou\\.co|buff\\.ly|ow\\.ly|tgig\\.ir)/(?=.{,200}$)"
        );
const boost::regex shortened_url_answer_r(
        "(?is)://(?:w+\\.)?(goo\\.gl|bit\\.ly|bit\\.do|tinyurl\\.com|fb\\.me|cl\\.ly|t\\.co|is\\.gd|j\\.mp|tr\\.im|"
        "wp\\.me|alturl\\.com|tiny\\.cc|9nl\\.me|post\\.ly|dyo\\.gs|bfy\\.tw|amzn\\.to|adf\\.ly|adfoc\\.us|"
        "surl\\.cn\\.com|clkmein\\.com|bluenik\\.com|rurl\\.us|adyou\\.co|buff\\.ly|ow\\.ly)/");

/* _TODO: Unicode support: edit `(?u)` in the starting of the following two regexes. */
/* _TODO: Recognize Latin and Cyrillic characters using Boost.Regex */
//const boost::regex word_chars_r("[\\W0-9]|http\\S*");
//const boost::regex non_latin_r("\\p{script=Latin}|\\p{script=Cyrillic}");

/* General regexes and other things, used across multiple reasons */
std::string se_sites_s ("(?:(?:[a-z]+\\.)*stackoverflow\\.com|(?:askubuntu|superuser|serverfault" 
        "|stackapps|imgur)\\.com|mathoverflow\\.net|(?:[a-z]+\\.)*stackexchange\\.com)");
const boost::regex se_sites_re(se_sites_s);
const boost::regex se_sites_url_re(fmt::sprintf("^https?://%s", se_sites_s));
const boost::regex whitelisted_websites_regex (
        "(?i)upload|\\x08(?:yfrog|gfycat|tinypic|sendvid|ctrlv|prntscr|gyazo|youtu\\.?be|"
        "past[ie]|dropbox|microsoft|newegg|cnet|regex101|(?<!plus\\.)google|localhost|ubuntu|"
        "getbootstrap|jsfiddle\\.net|codepen\\.io|pastebin|stackoverflow\\.com|askubuntu\\.com"
        "|superuser\\.com|serverfault\\.com|mathoverflow\\.net|stackapps\\.com|stackexchange\\.com"
        "|sstatic\\.net|imgur\\.com)\\x08");
const boost::regex url_re ("(?i)<a href=\"https?://\\S+");
const boost::regex link_re("<a href=\"([^\"]+)\"[^>]*>([^<]+)<\\/a>");
const boost::regex all_but_digits_re("[^\\d]");

std::vector<std::string> se_sites_domains = {
    "stackoverflow.com", "askubuntu.com", "superuser.com", "serverfault.com", "mathoverflow.net",
    "stackapps.com", "stackexchange.com", "sstatic.net", "imgur.com"};

/* Patterns: the top four lines are the most straightforward, matching any site with this string in domain name */
std::vector<std::string> pattern_websites = {
    
    "(enstella|recoverysoftware|removevirus|support(number|help|quickbooks)|techhelp|calltech|exclusive|"
    "onlineshop|video(course|classes|tutorial(?!s))|vipmodel|(?<!word)porn|wholesale|inboxmachine|(get|buy)cheap|"
    "escort|diploma|(govt|government)jobs|extramoney|earnathome|spell(caster|specialist)|profits|"
    "seo-?(tool|service|trick|market)|onsale|fat(burn|loss)|(\\.|//|best)cheap|online-?(training|solution)"
    "|\\bbabasupport\\b|movieshook|where\\w*to\\w*buy)"
    "[\\w-]*\\.(com?|net|org|in(\\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\\.)|info)",
    "(replica(?!t)|rs\\d?gold|rssong|runescapegold|maxgain|e-cash|mothers?day|phone-?number|fullmovie|tvstream|"
    "trainingin|dissertation|(placement|research)-?(paper|statement|essay)|digitalmarketing|infocampus|freetrial|"
    "cracked\\w{3}|bestmover|relocation|\\w{4}mortgage|revenue|testo[-bsx]|cleanse|cleansing|detox|suppl[ei]ment|"
    "loan|herbal|serum|lift(eye|skin)|(skin|eye)lift|luma(genex|lift)|renuva|svelme|santeavis|wrinkle|topcare)"
    "[\\w-]*\\.(com?|net|org|in(\\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\\.)|info)",
    "(drivingschool|crack-?serial|serial-?(key|crack)|freecrack|appsfor(pc|mac)|probiotic|remedies|heathcare|"
    "sideeffect|meatspin|packers\\S{0,3}movers|(buy|sell)\\S{0,12}cvv|goatse|burnfat|gronkaffe|muskel|"
    "tes(tos)?terone|nitric(storm|oxide)|masculin|menhealth|intohealth|babaji|spellcaster|potentbody|slimbody|"
    "slimatrex|moist|lefair|derma(?![nt])|xtrm|factorx|(?<!app)nitro(?!us)|endorev|ketone)"
    "[\\w-]*\\.(com?|net|org|in(\\W|fo)|us|ir|wordpress|blogspot|tumblr|webs(?=\\.)|info)",
    "(moving|\\w{10}spell|[\\w-]{3}password|(?!greatfurniture)\\w{5}deal|(?!nfood)\\w{5}facts|\\w\\dfacts|\\Btoyshop|"
    "[\\w-]{5}cheats|"
    "(?!djangogirls\\.org(?:$|[/?]))[\\w-]{6}girls|"
    "clothing|shoes(inc)?|cheatcode|cracks|credits|-wallet|refunds|truo?ng|viet|"
    "trang)\\.(co|net|org|in(\\W|fo)|us)",
    "(health|earn|max|cash|wage|pay|pocket|cent|today)[\\w-]{0,6}\\d+\\.com",
    "(//|www\\.)healthy?\\w{5,}\\.com",
    "https?://[\\w.-]\\.repair\\W", "https?://[\\w.-]{10,}\\.(top|help)\\W",
    "filefix(er)?\\.com", 
    "\\.page\\.tl\\W", 
    "infotech\\.(com|net|in)",
    "\\.(com|net)/(xtra|muscle)[\\w-]", 
    "http\\S*?\\Wfor-sale\\W",
    "fifa\\d+[\\w-]*?\\.com", 
    "[\\w-](giveaway|jackets|supplys|male)\\.com",
    "((essay|resume|click2)\\w{6,}|(essays|(research|term)paper|examcollection|[\\w-]{5}writing|"
    "writing[\\w-]{5})[\\w-]*?)\\.(com?|net|org|in(\\W|fo)|us|us)",
    "(top|best|expert)\\d\\w{0,15}\\.in\\W", 
    "\\dth(\\.co)?\\.in",
    /* _TODO: V */
    //"(jobs|in)\\L<city>\\.in",
    /* Epoch has been hastily reduced to `epoc` for a fixed-width lookbehind. */
    "[\\w-](recovery|repairs?|rescuer|(?<!epoc|font)converter)(pro|kit)?\\.(com|net)",
    "(corrupt|repair)[\\w-]*?\\.blogspot",
    "http\\S*?(yahoo|gmail|hotmail|outlook|office|microsoft)?[\\w-]{0,10}"
    "(account|tech|customer|support|service|phone|help)[\\w-]{0,10}(service|"
    "care|help|recovery|support|phone|number)",
    "http\\S*?(essay|resume|thesis|dissertation|paper)-?writing",
    "fix[\\w-]*?(files?|tool(box)?)\\.com", 
    "(repair|recovery|fix)tool(box)?\\.(co|net|org)",
    "smart(pc)?fixer\\.(co|net|org)",
    "password[\\w-]*?(cracker|unlocker|reset|buster|master|remover)\\.(co|net)",
    "crack[\\w-]*?(serial|soft|password)[\\w-]*?\\.(co|net)",
    "(downloader|pdf)converter\\.(com|net)",
    "ware[\\w-]*?download\\.(com|net|info|in\\W)",
    "((\\d|\\w{3})livestream|livestream(ing|s))[\\w]*?\\.(com|net|tv)", 
    "\\w+vs\\w+live\\.(com|net|tv)",
    "(play|watch|cup|20)[\\w\\-]*?(live|online)\\.(com|net|tv)", 
    "worldcup\\d[\\w-]*?\\.(com|net|tv|blogspot)",
    "https?://(\\w{5,}tutoring\\w*|cheat[\\w.-]{3,}|xtreme[\\w-]{5,})\\.",
    "(platinum|paying|acai|buy|premium|premier|ultra|thebest|best|[/.]try)[\\w]{10,}\\.(co|net|org|in(\\W|fo)|us)",
    "(training|institute|marketing)[\\w-]{6,}[\\w.-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "[\\w-](courses?|training)[\\w-]*?\\.in/",
    "\\w{9}(buy|roofing)\\.(co|net|org|in(\\W|fo)|us)",
    /* (something)health.(something)*/
    "(vitamin|dive|hike|love|strong|ideal|natural|pro|magic|beware|top|best|free|cheap|allied|nutrition|"
    "prostate)[\\w-]*?health[\\w-]*?\\.(co|net|org|in(\\W\\|fo)|us|wordpress|blogspot|tumblr|webs\\.)",
    /* (something)cream.(something) */
    "(eye|skin|age|aging)[\\w-]*?cream[\\w-]*?\\.(co|net|org|in(\\W|fo)|us|wordpress|blogspot|tumblr|webs\\.)",
    /* (keyword)(something)(keyword)(something).(something) */
    "(acai|advance|aging|alpha|beauty|belle|beta|biotic|body|boost(?! solution)|brain(?!tree)|burn|colon|"
    "[^s]cream|cr[eè]me|derma|ecig|eye|face(?!book)|fat|formula|geniu[sx]|grow|hair|health|herbal|ideal|luminous|"
    "male|medical|medicare|muscle|natura|no2|nutrition|optimal|pearl|perfect|phyto|probio|rejuven|revive|ripped|"
    "rx|scam|shred|skin|slim|super|testo|[/.]top|trim|[/.]try|ultra|ultra|vapor|vita|weight|wellness|xplode|yoga|"
    "young|youth)[\\w]{0,20}(about|advi[sc]|assess|blog|brazil|canada|care|center|centre|chat|complex(?!ity)|"
    "congress|consult|critic|critique|cure|denmark|discussion|doctor|dose|essence|essential|extract|fact|formula|"
    "france|funct?ion|genix|guide|help|idea|info|jacked|l[iy]ft|mag|market|max|mexico|norway|nutrition|order|plus|"
    "points|policy|potency|power|practice|pro|program|report|review|rewind|site|slim|solution|suppl(y|ier)|sweden|"
    "tip|trial|try|world|zone)[.\\w-]{0,12}\\.(co|net|org|in(\\W|fo)|us|wordpress|blogspot|tumblr|webs\\.)",
    "(\\w{11}(idea|income|sale)|\\w{6}(<?!notebook)(advice|problog|review))s?\\.(co|net|in(\\W|fo)|us)",
    "-(poker|jobs)\\.com", "send[\\w-]*?india\\.(co|net|org|in(\\W|fo)|us)",
    "(file|photo|android|iphone)recovery[\\w\\-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "(videos?|movies?|watch)online[\\w-]*?\\.", "hd(video|movie)[\\w-]*?\\.",
    "backlink(?!(o\\.|watch))[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "(replica[^nt]\\w{5,}|\\wrolex)\\.(co|net|org|in(\\W|fo)|us)",
    "customer(service|support)[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "conferences?alert[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "seo\\.com(?!/\\w)", 
    "\\Wseo(?!sitecheckup)[\\w-]{10,}\\.(com|net|in\\W)",
    "(?<!site)24x7[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "backlink[\\w-]*?\\.(com|net|de|blogspot)",
    "(software|developers|packers|movers|logistic|service)[\\w-]*?india\\.(com|in\\W)",
    "scam[\\w-]*?(book|alert|register|punch)[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "http\\S*?crazy(mass|bulk)", 
    "http\\S*\\.com\\.com[/\"<]",
    "https?://[^/\\s]{8,}healer",
    "reddit\\.com/\\w{6}/\"",
    "world[\\w-]*?cricket[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "(credit|online)[\\w-]*?loan[\\w-]*?\\.(co|net|org|in(\\W|fo)|us)",
    "worldcup\\d+live\\.(com?|net|org|in(\\W|fo)|us)",
    "((concrete|beton)-?mixer|crusher)[\\w-]*?\\.(co|net)",
    "\\w{7}formac\\.(com|net|org)",
    "sex\\.(com|net|info)", "https?://(www\\.)?sex",
    "[\\w-]{12}\\.(webs|66ghz)\\.com", 
    "online\\.us[/\"<]",
    "ptvsports\\d+.com",
    "youth\\Wserum",
    "buyviewsutube",
    "(?:celebrity-?)?net-?worth", 
    "richestcelebrities",
    "ufc\\wfight\\wnight" /* Chiesa vs Lee spam */
};

const boost::regex pattern_websites_r(fmt::sprintf("(?i)((%s)|[\\w-]*?(%s)[\\w-]*?\\.(com?|net|org|in(fo)?|us|blogspot|wordpress))(?![^>]*<)",
            join(pattern_websites, '|'), join(all_lists.bad_keywords_nwb.elements, '|')));
const boost::regex pattern_websites_ext_1_r(
        "(?i)\\b(?:[\\w-]{6,}|\\w*shop\\w*)(australia|brazil|canada|denmark|france|india|mexico|norway"
        "|pakistan|spain|sweden)\\w{0,4}\\.(com|net)");
const boost::regex pattern_websites_ext_2_r("(?i)http\\S*?(?<![/.]tcl)\\.(ir|pk|tk)(?=[/\"<])");
const boost::regex pattern_websites_ext_3_r(
        "(?i)(bodybuilding|workout|fitness(?!e)|diet|perfecthealth|muscle|nutrition(?!ix)|"
        "prostate)[\\w-]*?\\.(com|co\\.|net|org|info|in\\W)");

