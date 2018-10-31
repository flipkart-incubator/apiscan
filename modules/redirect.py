import sendrequest as req
import utils.logs as logs
import os
import urlparse

from itertools import islice
from utils.logger import Logger
from utils.db import DatabaseUpdate
from utils.config import get_value

dbupdate = DatabaseUpdate()
api_logger = Logger()

redirection_url = "www.google.com"


def fetch_open_redirect_payload():
    # Returns open redirect payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/redirect.txt'
    else:
        path = 'Payloads/redirect.txt'

    with open(path) as f:
        for line in islice(f, 1, None):
            if line:
                payload_list.append(line.rstrip())

    return payload_list


def fetch_redirection_names():
    # Returns the list of common open redirection param names
    redirection_names = get_value('scan.property', 'modules',
                                  'open-redirection-names')
    return redirection_names.split(',')


def redirection_post_method(url, method, headers, body, scanid):
    # Check for POST based open redirection.
    temp_body = {}
    for key, value in body.items():
        param_names = fetch_redirection_names()
        for name in param_names:
            if key == name:
                payloads = fetch_open_redirect_payload()
                for payload in payloads:
                    if "=" in payload:
                        payload = payload[payload.find('=') + 1:].replace(
                            '{target}', redirection_url)
                    else:
                        payload = payload.replace('{target}', redirection_url)

                    temp_body.update(body)
                    temp_body[key] = payload
                    post_req = req.api_request(url, "POST", headers, temp_body)
                    if str(post_req.status_code)[0] == '3':
                        if (post_req.headers['Location']
                                .startswith(redirection_url) is True):
                            print "%s[Medium] {0} is vulnerable to open " \
                                  "redirection%s".format(url)\
                                  % (api_logger.Y, api_logger.W)
                            logs.logging.info(
                                "%s is vulnerable to open redirection", url)
                            attack_result = {"id": 12, "scanid": scanid,
                                             "url": url,
                                             "alert": "Open redirection",
                                             "impact": "Medium",
                                             "req_headers": headers,
                                             "req_body": body,
                                             "res_headers": post_req.headers,
                                             "res_body": "NA"}
                            dbupdate.insert_record(attack_result)
                            return


def redirection_get_uri(url, method, headers, body, scanid):
    # This function checks for URI based redirection.
    # Ex: http://localhost?url=<redirection URL>
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    for key, value in parsed_query.items():
        redirect_name = fetch_redirection_names()
        for name in redirect_name:
            if name == key:
                redirection_payload = fetch_open_redirect_payload()
                for payload in redirection_payload:
                    if '=' in payload:
                        payload = payload[payload.find('=') + 1:].replace(
                            '{target}', redirection_url)
                    else:
                        payload = payload.replace('{target}', redirection_url)
                    parsed_url = urlparse.urlparse(url)
                    redirect_url = (
                            parsed_url.scheme + "://"
                            + parsed_url.netloc + parsed_url.path
                            + "/?"
                            + parsed_url.query.replace(value[0], payload))
                    fuzz_req = req.api_request(redirect_url, "GET", headers)
                    if str(fuzz_req.status_code)[0] == '3':
                        if fuzz_req.headers['Location'].startswith(
                                redirection_url) is True:
                            print "%s[Medium] {0} is vulnerable to open " \
                                  "redirection%s".format(url)\
                                  % (api_logger.Y, api_logger.W)
                            logs.logging.info(
                                "%s is vulnerable to open redirection",
                                redirect_url)
                            attack_result = {"id": 12, "scanid": scanid,
                                             "url": redirect_url,
                                             "alert": "Open redirection",
                                             "impact": "Medium",
                                             "req_headers": headers,
                                             "req_body": body,
                                             "res_headers": fuzz_req.headers,
                                             "res_body": "NA"}
                            dbupdate.insert_record(attack_result)
                            return


def fuzz_url(url, method, headers, body, scanid):
    # Fuzzing target URL with different params.
    parsed_url = urlparse.urlparse(url)
    target_domain = parsed_url.scheme + "://" + parsed_url.netloc + "/"
    redirect_payload = fetch_open_redirect_payload()
    for payload in redirect_payload:
        try:
            target_url = target_domain + payload.replace("{target}",
                                                         redirection_url)
        except:
            target_url = str(target_domain) + str(payload)

        fuzz_req = req.api_request(target_url, "GET", headers)
        if str(fuzz_req.status_code)[0] == '3':
            if fuzz_req.headers['Location'].startswith(redirection_url):
                print "%s[ Medium ] {0} is vulnerable to open redirection%s"\
                          .format(url) % (api_logger.Y, api_logger.W)
                logs.logging.info("%s is vulnerable to open redirection", url)
                attack_result = {"id": 12, "scanid": scanid, "url": target_url,
                                 "alert": "Open redirection",
                                 "impact": "Medium", "req_headers": headers,
                                 "req_body": body,
                                 "res_headers": fuzz_req.headers,
                                 "res_body": "NA"}
                dbupdate.insert_record(attack_result)
                return


def open_redirect_check(url, method, headers, body, scanid=None):
    # main function for open redirection.
    if method == 'GET':
        redirection_get_uri(url, method, headers, body, scanid)
    if method == 'POST':
        redirection_post_method(url, method, headers, body, scanid)
    fuzz_url(url, method, headers, body, scanid)
