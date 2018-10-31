import jwt
import base64
import ast
import urlparse
import sendrequest as req

from utils.logger import Logger
from utils.db import DatabaseUpdate
from utils.config import get_value

dbupdate = DatabaseUpdate()
api_logger = Logger()


# This module identifies different JWT vulnerabilities which includes:
# 1. JWT none algorithm vulnerability
# 2. Weak JWT Sign key

def decode_jwt(jwt_token):
    # Return the decoded value of alg and data
    jwt_decode_list = []
    try:
        jwt_list = jwt_token.split('.')
        for token in jwt_list:
            missing_padding = len(token) % 4
            if missing_padding != 0:
                token += b'=' * (4 - missing_padding)
            jwt_decode_list.append(base64.decodestring(token))
    except:
        pass

    return jwt_decode_list


def jwt_none(url, method, headers, body, jwt_loc, jwt_key, jwt_token, jwt_data,
             scanid=None):
    # Check for algo None vulnerability.
    encoded_jwt = jwt.encode(jwt_data, '', algorithm='none')
    if jwt_loc == "url":
        url = url.replace(value[0], encoded_jwt)
    if jwt_loc == "header":
        headers[key] = encoded_jwt

    jwt_request = req.api_request(url, method, headers, body)
    if (str(jwt_request.status_code)[0] == '5' or
            str(jwt_request.status_code)[0] == '4'):
        pass
    else:
        print "%s[+]API is vulnearalbe to JWT none algo vulnerability%s"\
                  .format(url) % (api_logger.R, api_logger.W)
        attack_result = {
            "id": 8,
            "scanid": scanid,
            "url": url,
            "alert": "JWT none Algorithm vulnerability",
            "impact": "High",
            "req_headers": headers,
            "req_body": body,
            "res_headers": jwt_request.headers,
            "res_body": jwt_request.text

        }

        dbupdate.insert_record(attack_result)
        return True


def find_jwt(url, headers):
    # This function deals with identifying JWT token from HTTP request.
    # Identify JWT token from URL
    query_list = []
    global key, value
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    for key, value in parsed_query.items():
        try:
            jwt_token = jwt.decode(value[0], verify=False)
            return "url", key, value[0]
        except:
            pass

    # Identify JWT token from headers
    for key, value in headers.items():
        try:
            jwt_token = jwt.decode(value, verify=False)
            return "header", key, value
        except:
            pass

    return None, None, None


def jwt_brute(url, headers, body, jwt_token, jwt_alg, scanid=None):
    # JWT token brute force
    with open('secret.txt') as sign_keys:
        for sign_key in sign_keys:
            try:
                jwt.decode(jwt_token, sign_key.rstrip(), algorithms=[jwt_alg])
                print "%s[+]Weak JWT sign key found:{0}%s".format(
                    sign_key.rstrip()) % (api_logger.R, api_logger.W)
                alert = "Weak JWT sign key:" + sign_key.rstrip()
                attack_result = {
                    "id": 9,
                    "scanid": scanid,
                    "url": url,
                    "alert": alert,
                    "impact": "High",
                    "req_headers": headers,
                    "req_body": body,
                    "res_headers": "NA",
                    "res_body": "NA"

                }
                print "attack result", attack_result

                dbupdate.insert_record(attack_result)

            except:
                pass


def jwt_check(url, method, headers, body, scanid):
    # Main function for JWT test
    jwt_loc, jwt_key, jwt_token = find_jwt(url, headers)
    if jwt_loc is None:
        return
    jwt_decoded_list = decode_jwt(jwt_token)
    if jwt_decoded_list:
        alg = ast.literal_eval(jwt_decoded_list[0])['alg']
        jwt_data = ast.literal_eval(jwt_decoded_list[1])
        if alg == 'HS256' or alg == 'HS512' or alg == 'HS384':
            result = jwt_none(url, method, headers, body, jwt_loc, jwt_key,
                              jwt_token, jwt_data)
            if result is True:
                pass
            else:
                arg = get_value('scan.property', 'modules', 'jwt_brute')
                if arg == 'Y' or arg == 'y':
                    jwt_brute(url, headers, body, jwt_token, alg, scanid)
