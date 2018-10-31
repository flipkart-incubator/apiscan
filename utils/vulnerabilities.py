# -*- coding: utf-8 -*-

alerts = [

    {
        "id": 1,
        "name": "CORS Misconfiguration",
        "Description": "CORS misconfiguration allows attacker to send a cross "
                       "domain request and can read arbitrary data of other "
                       "users",
        "remediation": "Validate origin header and allow only http request "
                       "from trusted domain"
    },

    {
        "id": 3,
        "name": "Broken Authentcation and Session Management",
        "Description": "API is not verifying authentication for "
                       "functionality on server side that allows attacker to "
                       "access unauthorized resource.",
        "remediation": "Developers frequently build custom authentication and "
                       "session management schemes, but building these "
                       "correctly is hard. As a result, these custom schemes "
                       "frequently have flaws in areas such as logout, "
                       "password management, timeouts, remember me, "
                       "secret question, account update, etc. Finding such "
                       "flaws can sometimes be difficult, as each "
                       "implementation is unique."
    },

    {
        "id": 4,
        "name": "Missing Authentication",
        "Description": "API does not perform any authentication for "
                       "functionality that requires a provable user identity "
                       "or consumes a significant amount of resources.",
        "remediation": "Developers frequently build custom authentication and "
                       "session management schemes, but building these "
                       "correctly is hard. As a result, these custom schemes "
                       "frequently have flaws in areas such as logout, "
                       "password management, timeouts, remember me, secret "
                       "question, account update, etc. Finding such flaws "
                       "can sometimes be difficult, as each implementation "
                       "is unique."
    },

    {
        "id": 5,
        "name": "Session Fixation",
        "Description": "Session Fixation is an attack that permits an "
                       "attacker to hijack a valid user session. The attack "
                       "explores a limitation in the way the web application "
                       "manages the session ID, more specifically the "
                       "vulnerable web application. When authenticating a "
                       "user, it doesn't assign a new session ID, making it "
                       "possible to use an existing session ID. The attack "
                       "consists of obtaining a valid session ID (e.g. by "
                       "connecting to the application), inducing a user to "
                       "authenticate himself with that session ID, and then "
                       "hijacking the user-validated session by the knowledge "
                       "of the used session ID. The attacker has to provide a "
                       "legitimate Web application session ID and try to make "
                       "the victim's browser use it.",
        "remediation": "Simply discarding any existing session is sufficient "
                       "to force the framework to issue a new sessionid "
                       "cookie, with a new value."
    },
    {
        "id": 6,
        "name": "Cross-Site Request Forgery",
        "Description": "CSRF is an attack that tricks the victim into "
                       "submitting a malicious request. It inherits the "
                       "identity and privileges of the victim to perform "
                       "an undesired function on the victim's behalf. For "
                       "most sites, browser requests automatically include "
                       "any credentials associated with the site, such as "
                       "the user's session cookie, IP address, Windows domain "
                       "credentials, and so forth. Therefore, if the user is "
                       "currently authenticated to the site, the site will "
                       "have no way to distinguish between the forged request "
                       "sent by the victim and a legitimate request sent by "
                       "the victim.",
        "remediation": "The most common method to prevent Cross-Site Request "
                       "Forgery (CSRF) attacks is to append CSRF tokens to "
                       "each request and associate them with the user’s "
                       "session. Such tokens should at a minimum be unique "
                       "per user session, but can also be unique per request. "
                       "By including a challenge token with each request, the "
                       "developer can ensure that the request is valid and "
                       "not coming from a source other than the user."
    },

    {
        "id": 7,
        "name": "Missing Rate limit",
        "Description": "An attacker can always discover a password through a "
                       "brute-force attack, but the downside is that it could "
                       "take years to find it. Depending on the password's "
                       "length and complexity, there could be trillions of "
                       "possible combinations. To speed things up a bit, a "
                       "brute-force attack could start with dictionary words "
                       "or slightly modified dictionary words because most "
                       "people will use those rather than a completely random "
                       "password. These attacks are called dictionary attacks "
                       "or hybrid brute-force attacks. Brute-force attacks "
                       "put user accounts at risk and flood your site with "
                       "unnecessary traffic.",
        "remediation": "The most obvious way to block brute-force attacks is "
                       "to simply lock out accounts after a defined number of "
                       "incorrect password attempts. Account lockouts can "
                       "last a specific duration, such as one hour, or the "
                       "accounts could remain locked until manually unlocked "
                       "by an administrator. However, account lockout is not "
                       "always the best solution, because someone could "
                       "easily abuse the security measure and lock out "
                       "hundreds of user accounts"
    },

    {
        "id": 8,
        "name": "JWT none algorithm vulnerability",
        "Description": "Some libraries treated tokens signed with the none "
                       "algorithm as a valid token with a verified signature. "
                       "Anyone can create their own \"signed\" tokens with "
                       "whatever payload they want, allowing arbitrary "
                       "account access on some systems",
        "remediation": "Don't allow none algorithm"
    },

    {
        "id": 9,
        "name": "Weak JWT sign key",
        "Description": "Some libraries treated tokens signed with the none "
                       "algorithm as a valid token with a verified signature. "
                       "Anyone can create their own \"signed\" tokens with "
                       "whatever payload they want, allowing arbitrary "
                       "account access on some systems",
        "remediation": "Use strong key or use RS256 tokens."
    },
    {
        "id": 10,
        "name": "SQL injection",
        "Description": "SQL injection is a code injection technique, used to "
                       "attack data-driven applications, in which nefarious "
                       "SQL statements are inserted into an entry field for "
                       "execution (e.g. to dump the database contents to the "
                       "attacker).[1] SQL injection must exploit a security "
                       "vulnerability in an application's software, "
                       "for example, when user input is either incorrectly "
                       "filtered for string literal escape characters "
                       "embedded in SQL statements or user input is not "
                       "strongly typed and unexpectedly executed. SQL "
                       "injection is mostly known as an attack vector for "
                       "websites but can be used to attack any type of "
                       "SQL database.",
        "remediation": "With most development platforms, parameterized "
                       "statements that work with parameters can be used "
                       "(sometimes called placeholders or bind variables) "
                       "instead of embedding user input in the statement. A "
                       "placeholder can only store a value of the given type "
                       "and not an arbitrary SQL fragment. Hence the SQL "
                       "injection would simply be treated as a strange (and "
                       "probably invalid) parameter value."
    },
    {
        "id": 11,
        "name": "Cross site scripting",
        "Description": "Cross-Site Scripting (XSS) attacks are a type of "
                       "injection, in which malicious scripts are injected "
                       "into otherwise benign and trusted web sites. XSS "
                       "attacks occur when an attacker uses a web application "
                       "to send malicious code, generally in the form of a "
                       "browser side script, to a different end user. Flaws "
                       "that allow these attacks to succeed are quite "
                       "widespread and occur anywhere a web application uses "
                       "input from a user within the output it generates "
                       "without validating or encoding it.",
        "remediation": "In a Web 2.0 world, the need for having data "
                       "dynamically generated by an application in a "
                       "javascript context is common. One strategy is to make "
                       "an AJAX call to get the values, but this isn't always "
                       "performant. Often, an initial block of JSON is loaded "
                       "into the page to act as a single place to store "
                       "multiple values. This data is tricky, though not "
                       "impossible, to escape correctly without breaking the "
                       "format and content of the values. Ensure returned "
                       "Content-Type header is application/json and not "
                       "text/html. This shall instruct the browser not "
                       "misunderstand the context and execute injected script",
    },
    {
        "id": 12,
        "name": "Open redirection",
        "Description": "Unvalidated redirects and forwards are possible when "
                       "an application accepts untrusted input that could "
                       "cause an application to redirect the request to a URL "
                       "contained within untrusted input. By modifying "
                       "untrusted URL input to a malicious site, an attacker "
                       "may successfully launch a phishing scam and steal "
                       "user credentials. Because the server name in the "
                       "modified link is identical to the original site, "
                       "phishing attempts may have a more trustworthy "
                       "appearance. Unvalidated redirect and forward attacks "
                       "can also be used to maliciously craft a URL that "
                       "would pass the application’s access control check and "
                       "then forward the attacker to privileged functions "
                       "that they would normally not be able to access.",
        "remediation": "Sanitize input by creating a list of trusted URL's "
                       "(lists of hosts or a regex)."
    },
    {
        "id": 13,
        "name": "CRLF",
        "Description": "The term CRLF refers to Carriage Return (ASCII 13) "
                       "Line Feed (ASCII 10). They are used to note the "
                       "termination of a line, however, dealt with "
                       "differently in today’s popular Operating Systems. "
                       "For example: in Windows both a CR and LF are required "
                       "to note the end of a line, whereas in Linux/UNIX a LF "
                       "is only required. In the HTTP protocol, the CR-LF "
                       "sequence is always used to terminate a line.",
        "remediation": "Sanitise the CRLF characters before passing into the "
                       "header or to encode the data which will prevent the "
                       "CRLF sequences entering the header."
    },
    {
        "id": 14,
        "name": "XML External Entity Attack",
        "Description": "An XML External Entity attack is a type of attack "
                       "against an application that parses XML input. This "
                       "attack occurs when XML input containing a reference "
                       "to an external entity is processed by a weakly "
                       "configured XML parser. This attack may lead to the "
                       "disclosure of confidential data, denial of service, "
                       "server side request forgery, port scanning from the "
                       "perspective of the machine where the parser is "
                       "located, and other system impacts.",
        "remediation": "The XML processor should be configured to use a local "
                       "static DTD and disallow any declared DTD included in "
                       "the XML document."
    }
]
