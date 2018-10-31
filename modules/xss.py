import os
import sendrequest as req
import utils.logs as logs
import urlparse
import urllib

from utils.logger import Logger
from utils.db import DatabaseUpdate

dbupdate = DatabaseUpdate()
api_logger = Logger()


def fetch_xss_payload():
    # Returns xss payloads in list type
    payload_list = []
    if os.getcwd().split('/')[-1] == 'API':
        path = '../Payloads/xss.txt'
    else:
        path = 'Payloads/xss.txt'

    with open(path) as f:
        for line in f:
            if line:
                payload_list.append(line.rstrip())

    return payload_list


def check_xss_impact(res_headers):
    # Return the impact of XSS based on content-type header
    if res_headers['Content-Type']:
        if res_headers['Content-Type'].find('application/json') != -1 or \
                res_headers['Content-Type'].find('text/plain') != -1:
            # Possible XSS
            impact = "Low"
        else:
            impact = "High"
    else:
        impact = "Low"

    return impact


def xss_payload_decode(payload):
    # Return decoded payload of XSS.
    decoded_payload = urllib.unquote(payload).decode('utf8').encode('ascii',
                                                                    'ignore')
    return decoded_payload


def xss_post_method(url, method, headers, body, scanid=None):
    # This function checks XSS through POST method.
    temp_body = {}
    post_vul_param = ''
    db_update = ''
    for key, value in body.items():
        xss_payloads = fetch_xss_payload()
        for payload in xss_payloads:
            temp_body.update(body)
            temp_body[key] = payload
            xss_post_request = req.api_request(url, "POST", headers, temp_body)
            decoded_payload = xss_payload_decode(payload)
            if xss_post_request.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_post_request.headers)
                if db_update is not True:
                    attack_result = {"id": 11, "scanid": scanid, "url": url,
                                     "alert": "Cross Site Scripting",
                                     "impact": impact, "req_headers": headers,
                                     "req_body": temp_body,
                                     "res_headers": xss_post_request.headers,
                                     "res_body": xss_post_request.text}
                    dbupdate.insert_record(attack_result)
                    db_update = True
                    post_vul_param += key
                    break
                else:
                    if post_vul_param == '':
                        post_vul_param += key
                    else:
                        post_vul_param += ',' + key
                    break

    if post_vul_param:
        # Update all vulnerable params to db.
        logs.logging.info("%s Vulnerable Params:", post_vul_param)
        dbupdate.update_record({"scanid": scanid}, {
            "$set": {"scan_data": post_vul_param + " are vulnerable to XSS"}})


def xss_http_headers(url, method, headers, body, scanid=None):
    # This function checks different header based XSS.
    # XSS via Host header (Limited to IE)
    # Reference : http://sagarpopat.in/2017/03/06/yahooxss/
    temp_headers = {}
    temp_headers.update(headers)
    xss_payloads = fetch_xss_payload()
    for payload in xss_payloads:
        parse_domain = urlparse.urlparse(url).netloc
        host_header = {"Host": parse_domain + '/' + payload}
        temp_headers.update(host_header)
        host_header_xss = req.api_request(url, "GET", temp_headers)
        try:
            decoded_payload = xss_payload_decode(payload)
            if host_header_xss.text.find(decoded_payload) != -1:
                impact = "Low"
                logs.logging.info("%s is vulnerable to XSS", url)
                print "%s[{0}] {1} is vulnerable to XSS%s".format(impact,
                                                                  url) % (
                      api_logger.G, api_logger.W)
                attack_result = {"id": 11, "scanid": scanid, "url": url,
                                 "alert": "Cross Site Scripting",
                                 "impact": impact, "req_headers": headers,
                                 "req_body": body,
                                 "res_headers": host_header_xss.headers,
                                 "res_body": host_header_xss.text}
                dbupdate.insert_record(attack_result)
                break
        except:
            logs.logging.info("Failed to test XSS via Host header:%s", url)
            return

    # Test for Referer based XSS
    for payload in xss_payloads:
        referer_header_value = 'https://github.com?test=' + payload
        referer_header = {"Referer": referer_header_value}
        temp_headers.update(referer_header)
        ref_header_xss = req.api_request(url, "GET", temp_headers)
        decoded_payload = xss_payload_decode(payload)
        if ref_header_xss.text.find(decoded_payload) != -1:
            impact = check_xss_impact(temp_headers)
            logs.logging.info("%s is vulnerable to XSS", url)
            print "%s[{0}] {1} is vulnerable to XSS via referer header%s"\
                  .format(impact, url) % (api_logger.G, api_logger.W)
            attack_result = {
                "id": 11,
                "scanid": scanid,
                "url": url,
                "alert": "Cross Site Scripting via referer header",
                "impact": impact,
                "req_headers": temp_headers,
                "req_body": body,
                "res_headers": ref_header_xss.headers,
                "res_body": ref_header_xss.text}
            dbupdate.insert_record(attack_result)
            return


def xss_get_url(url, method, headers, body, scanid=None):
    # Check for URL based XSS.
    # Ex: http://localhost/<payload>, http://localhost//?randomparam=<payload>
    result = ''
    parsed_url = ''
    xss_payloads = fetch_xss_payload()
    uri_check_list = ['?', '&', '=', '%3F', '%26', '%3D']
    for uri_list in uri_check_list:
        if uri_list in url:
            # Parse domain name from URI.
            parsed_url = urlparse.urlparse(
                url).scheme + "://" + urlparse.urlparse(
                url).netloc + urlparse.urlparse(url).path
            break

    if parsed_url == '':
        parsed_url = url

    for payload in xss_payloads:
        decoded_payload = xss_payload_decode(payload)
        xss_request_url = req.api_request(parsed_url + '/' + payload, "GET",
                                          headers)
        if result is not True:
            if xss_request_url.text.find(decoded_payload) != -1:
                impact = check_xss_impact(xss_request_url.headers)
                attack_result = {"id": 11, "scanid": scanid, "url": url,
                                 "alert": "Cross Site Scripting",
                                 "impact": impact, "req_headers": headers,
                                 "req_body": body,
                                 "res_headers": xss_request_url.headers,
                                 "res_body": xss_request_url.text}
                dbupdate.insert_record(attack_result)
                result = True

        xss_request_uri = req.api_request(parsed_url + '/?test=' + payload,
                                          "GET", headers)
        if xss_request_uri.text.find(decoded_payload) != -1:
            impact = check_xss_impact(xss_request_uri.headers)
            logs.logging.info("%s is vulnerable to XSS", url)
            print "%s[{0}] {1} is vulnerable to XSS%s".format(impact, url) \
                  % (api_logger.G, api_logger.W)
            attack_result = {"id": 11, "scanid": scanid, "url": url,
                             "alert": "Cross Site Scripting", "impact": impact,
                             "req_headers": headers, "req_body": body,
                             "res_headers": xss_request_url.headers,
                             "res_body": xss_request_url.text}
            dbupdate.insert_record(attack_result)


def xss_get_uri(url, method, headers, body, scanid=None):
    # This function checks for URI based XSS.
    # http://localhost/?firstname=<payload>&lastname=<payload>
    db_update = ''
    vul_param = ''
    url_query = urlparse.urlparse(url)
    parsed_query = urlparse.parse_qs(url_query.query)
    if parsed_query:
        for key, value in parsed_query.items():
            try:
                result = ''
                logs.logging.info("GET param for xss : %s", key)
                xss_payloads = fetch_xss_payload()
                for payload in xss_payloads:
                    # check for URI based XSS
                    # Example:
                    #   http://localhost/?firstname=<payload>&lastname=<payload>
                    if result is not True:
                        parsed_url = urlparse.urlparse(url)
                        xss_url = (parsed_url.scheme +
                                   "://" + parsed_url.netloc +
                                   parsed_url.path + "?" +
                                   parsed_url.query.replace(value[0], payload))
                        xss_request = req.api_request(xss_url, "GET", headers)
                        decoded_payload = xss_payload_decode(payload)
                        if xss_request.text.find(decoded_payload) != -1:
                            impact = check_xss_impact(xss_request.headers)
                            logs.logging.info("%s is vulnerable to XSS", url)
                            print "%s[{0}] {1} is vulnerable to XSS%s".format(
                                impact, url) % (api_logger.G, api_logger.W)
                            if db_update is not True:
                                attack_result = {
                                    "id": 11, "scanid": scanid,
                                    "url": xss_url,
                                    "alert": "Cross Site Scripting",
                                    "impact": impact,
                                    "req_headers": headers,
                                    "req_body": body,
                                    "res_headers": xss_request.headers,
                                    "res_body": xss_request.text
                                }
                                dbupdate.insert_record(attack_result)
                                result, db_update = True, True
                                vul_param += key
                            else:
                                result = True
                                if vul_param == '':
                                    vul_param += key
                                else:
                                    vul_param += ',' + key

            except:
                pass

    else:
        logs.logging.info("XSS: No GET param found!")
        if vul_param:
            # Update all vulnerable params to db.
            logs.logging.info("%s Vulnerable Params:", vul_param)
            dbupdate.update_record({"scanid": scanid}, {"$set": {
                "scan_data": vul_param + " parameters are vulnerable to XSS"}})


def xss_check(url, method, headers, body, scanid):
    # Main function for XSS attack
    if method == 'GET' or method == 'DEL':
        xss_get_uri(url, method, headers, body, scanid)
        xss_get_url(url, method, headers, body, scanid)

    if method == 'POST' or method == 'PUT':
        xss_post_method(url, method, headers, body, scanid)

    xss_http_headers(url, method, headers, body, scanid)
