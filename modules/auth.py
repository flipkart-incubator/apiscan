import utils.logger as logger
import utils.logs as logs
import sendrequest as req
import ast
import base64
import sys

try:
    import requests

    requests.packages.urllib3.disable_warnings()
except:
    print "[-]Failed to import requests module"

sys.path.append('../')

from utils.db import DatabaseUpdate
from utils.config import get_value, get_allvalues
from core.login import APILogin

dbupdate = DatabaseUpdate()
api_logger = logger.Logger()
api_login = APILogin()


def get_authdata():
    # Fetching login and logout data
    login_data = get_allvalues('config.property', 'login')
    logout_data = get_allvalues('config.property', 'logout')
    return login_data, logout_data


def fetch_auth_config(name):
    # Returns the list of common authentication headers names
    # and auth error from config file.
    auth_config_value = get_value('scan.property', 'modules', name)
    return auth_config_value.split(',')


def session_fixation(url, method, headers, body, scanid):
    # This function deals with checking session fixation issue.
    attack_result = {}
    login_result = get_value('config.property', 'login', 'loginresult')
    logout_result = get_value('config.property', 'logout', 'logoutresult')
    if login_result == 'Y' and logout_result == 'Y':
        login_data, logout_data = get_authdata()
        if url == login_data['loginurl']:
            logs.logging.info("Checking for Sesion fixation: %s", url)
            url, method, headers, body = (
                logout_data['logouturl'],
                logout_data['logoutmethod'],
                logout_data['logoutheaders'],
                logout_data['logoutbody']
            )
            logout_headers, auth_old = add_authheader(headers)
            try:
                logout_body = ast.literal_eval(base64.b64decode(body))
            except:
                logout_body = None
            logs.logging.info("Logout request %s %s %s", url, logout_headers,
                              logout_body)
            logout_req = req.api_request(url, method, logout_headers,
                                         logout_body)
            if logout_req is None or str(logout_req.status_code)[0] == '4' or \
                    str(logout_req.status_code)[0] == '5':
                print "%s[!]Failed to logout. Session fixation attack won't" \
                      " be tested. Check log file for more information.%s"\
                      % (api_logger.Y, api_logger.W)
                return
            # Try to relogin and check if the application is serving the
            # previous session
            login_url, login_method, login_headers, login_body = (
                login_data['loginurl'],
                login_data['loginmethod'],
                login_data['loginheaders'],
                login_data['loginbody'])
            logs.logging.info("Login request %s %s %s", url, headers, body)
            login_req = api_login.fetch_logintoken(
                login_url,
                login_method,
                ast.literal_eval(login_headers),
                ast.literal_eval(login_body)
            )
            if login_req is True:
                logs.logging.info("Relogin Successful")
                auth_new = get_value('config.property', 'login', 'auth')
                if auth_old == auth_new:
                    attack_result.update({"id": 5,
                                          "scanid": scanid,
                                          "url": login_url,
                                          "alert": "Session Fixation",
                                          "impact": "Medium",
                                          "req_headers": login_headers,
                                          "req_body": req_body,
                                          "res_headers": "NA",
                                          "res_body": "NA"
                                          })

                    dbupdate.insert_record(attack_result)


def auth_check(url, method, headers, body, scanid=None):
    # This function removes auth header and check if server is accepting
    # request without it
    temp_headers = {}
    temp_headers.update(headers)
    try:
        attack_result = {}
        auth_headers = fetch_auth_config("auth_headers")
        auth_fail = fetch_auth_config("auth_fail")
        session_headers = headers
        for auth_header in auth_headers:
            for key, value in temp_headers.items():
                if key.lower() == auth_header.lower():
                    del temp_headers[auth_header]
                    updated_headers = temp_headers
                    logs.logging.info("Auth header is %s", auth_header)
                    auth_request = req.api_request(url,
                                                   method,
                                                   updated_headers,
                                                   body)
                    if auth_request.status_code == 401:
                        logs.logging.info(
                            "API requires authentication hence it's not "
                            "vulnerable %s",
                            url)
                        return
                    elif (auth_request.status_code == 200 or
                          auth_request.status_code == 400):
                        # Check for false positive
                        for fail_name in auth_fail:
                            if (fail_name.lower() in
                                    auth_request.content.lower()):
                                logs.logging.info(
                                    "API requires authentication hence it's "
                                    "not vulnerable %s",
                                    url)
                            else:
                                attack_result.update({
                                    "id": 3,
                                    "scanid": scanid,
                                    "url": url,
                                    "alert": "Broken Authentication and "
                                             "session management",
                                    "impact": "High",
                                    "req_headers": updated_headers,
                                    "req_body": body,
                                    "res_headers": auth_request.headers,
                                    "res_body": auth_request.text
                                })

                                dbupdate.insert_record(attack_result)
                                print "%s[+]{0} is vulnerable to broken " \
                                      "Authentication and session " \
                                      "management %s ".format(url) \
                                      % (api_logger.R, api_logger.W)
                                return

                    session_fixation(url, method, temp_headers, body, scanid)

                else:
                    result = False

        if result is False:
            # Marking it as vulnerable if there has no authentication header
            # present in HTTP request
            brokenauth_request = req.api_request(url, method, headers, body)
            attack_result.update({
                "id": 4,
                "scanid": scanid,
                "url": url,
                "alert": "Broken Authentication and session management",
                "impact": "High",
                "req_headers": headers,
                "req_body": body,
                "res_headers": brokenauth_request.headers,
                "res_body": brokenauth_request.text
            })
            dbupdate.insert_record(attack_result)
            print "%s[+]{0} is vulnerable to broken Authentication and " \
                  "session management %s ".format(url)\
                  % (api_logger.R, api_logger.W)
            # Test for session fixation
            session_fixation(url, method, updated_headers, body, scanid)
            return
    except:
        pass
