import sendrequest as req
import sys
import random
import string

from utils.db import DatabaseUpdate
from headers import request_headers, csrf_headers
from utils.config import get_value
from utils.logger import Logger
from cors import check_custom_header

dbupdate = DatabaseUpdate()
api_logger = Logger()


def create_headerlist(http_headers):
    # Return the headers in list type
    headers_list = []
    for key in http_headers:
        headers_list.append(key)
    return headers_list


def csrf_request(url, method, headers, body):
    # Send orginal request without removing CSRF header or param.
    try:
        http_request = req.api_request(url, method, headers, body)
        return http_request.status_code, len(http_request.text)
    except Exception as e:
        sys.exit(1)


def csrf_header_remove(headers, csrf_header):
    # Return request header after deleting CSRF header.
    del headers[csrf_header]
    return headers


def generate_csrf_token(csrf_header_value):
    # Return the new value of CSRF token.
    length = len(csrf_header_value)
    new_csrf_value = ''.join(
        random.choice(string.ascii_letters) for i in range(length))
    return new_csrf_value


def csrf_attack_body(url, method, headers, body, csrf_param, scanid):
    tmp_headers = {}
    http_status_code, response_size = csrf_request(url, method, headers, body)
    if csrf_param is not None:
        csrf_param_value = generate_csrf_token(str(body['csrf_param']))
        body['csrf_param'] = csrf_param_value

    csrf_req_body = req.api_request(url, method, headers, body)
    if str(csrf_req_body.status_code)[0] == '4' or \
            str(csrf_req_body.status_code)[0] == '5':
        return

    if csrf_req_body.status_code == http_status_code:
        if len(csrf_req_body.text) == response_size:
            # Testing for JSON based CSRF - Blind CSRF
            tmp_headers.update(headers)
            tmp_headers['Content-Type'] = 'text/plain'
            json_csrf = req.api_request(url, method, tmp_headers, body)
            if str(json_csrf.status_code)[0] == '4' or \
                    str(json_csrf.status_code)[0] == '5':
                # Application is validating content-type header.
                # Only way to bypass is using flash based technique.
                impact = "Medium"
            else:
                impact = "High"
                headers = tmp_headers

            print "%s[-]{0} is vulnerable to CSRF attack%s".format(url) % (
                api_logger.R, api_logger.W)
            attack_result = {"id": 6, "scanid": scanid, "url": url,
                             "alert": "CSRF", "impact": impact,
                             "req_headers": headers, "req_body": body,
                             "res_headers": json_csrf.headers,
                             "res_body": json_csrf.text}
            dbupdate.insert_record(attack_result)


def csrf_attack_header(url, method, headers, body, csrf_header, csrf_test_type,
                       scanid):
    # This function performs CSRF attack with various techniques.
    if csrf_test_type == "header":
        updated_headers = headers.copy()
        http_status_code, response_size = csrf_request(url, method, headers,
                                                       body)
        # Delete the CSRF header and send the request
        updated_headers = csrf_header_remove(updated_headers, csrf_header)
        csrf_req = req.api_request(url, method, updated_headers, body)

        if (str(csrf_req.status_code)[0] == '4' or
                str(csrf_req.status_code)[0] == '5'):
            return

        if csrf_req.status_code == http_status_code:
            if len(csrf_req.text) == response_size:
                print "%s[-]{0} is vulnerable to CSRF attack%s" \
                          .format(url) % (api_logger.R, api_logger.W)
                attack_result = {"id": 6, "scanid": scanid, "url": url,
                                 "alert": "CSRF", "impact": "High",
                                 "req_headers": headers,
                                 "res_headers": csrf_req.headers,
                                 "res_body": csrf_req.text}
                dbupdate.insert_record(attack_result)
                return

        try:
            csrf_header_value = headers[csrf_header]
            csrf_header_value = generate_csrf_token(str(csrf_header_value))
            # Updating CSRF value. Ex X-XSRF-token : xyz
            headers[csrf_header] = csrf_header_value
            new_csrf_req = req.api_request(url, method, updated_headers, body)
            if (str(csrf_req.status_code)[0] == '4' or
                    str(csrf_req.status_code)[0] == '5'):
                return

            if csrf_req.status_code == http_status_code:
                if len(csrf_req.text) == response_size:
                    # Check for CORS
                    result = check_custom_header(url, csrf_header)
                    if result:
                        print "%s[-]{0} is vulnerable to CSRF attack%s".format(
                            url) % (api_logger.R, api_logger.W)
                        attack_result = {"id": 6, "scanid": scanid, "url": url,
                                         "alert": "CSRF", "impact": "High",
                                         "req_headers": headers,
                                         "req_body": body,
                                         "res_headers": csrf_req.headers,
                                         "res_body": csrf_req.text}
                        dbupdate.insert_record(attack_result)

        except Exception:
            return


def fetch_csrf_names():
    # Returns the list of common CSRF token param names from config file.
    csrf_names = get_value('scan.property', 'modules', 'csrftoken-names')
    return csrf_names.split(',')


def verify_body(body):
    # Return the param name of CSRF
    common_names = fetch_csrf_names()
    for csrf_name in common_names:
        for key, value in body.items():
            if csrf_name == key:
                return csrf_name
    return False


def verify_headers(headers):
    # Check if any CSRF header present in HTTP headers. Example: X-XSRF-TOKEN
    custom_header = ''
    headers_list = create_headerlist(headers)
    for common_header in csrf_headers:
        if common_header in headers_list:
            # found the common CSRF header
            custom_header = common_header
            break
        else:
            common_header = False

    # check if any custom header is being used as CSRF protection.
    # Example : x-user-agent
    if common_header is False:
        for http_header in headers_list:
            if http_header in request_headers:
                pass
            else:
                custom_header = http_header  # Custom CSRF header detected
                break

    return custom_header


def csrf_check(url, method, headers, body, scanid=None):
    try:
        if method == "POST" or method == "PUT" or method == "DEL":
            csrf_header = verify_headers(headers)
            if csrf_header:
                csrf_attack_header(url, method, headers, body, csrf_header,
                                   "header", scanid)
            else:
                csrf_param = verify_body(body)
                if csrf_param is not False:
                    csrf_attack_body(url, method, headers, body, csrf_param,
                                     scanid)
                else:
                    csrf_attack_body(url, method, headers, body, None, scanid)
                # No CSRF protection.

    except Exception as e:
        raise e
