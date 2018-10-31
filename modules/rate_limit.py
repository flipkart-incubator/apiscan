import utils.logger as logger
import sendrequest as req
import random
import string
import sys

sys.path.append('../')

from utils.db import DatabaseUpdate
from utils.config import get_value
from core.login import APILogin

dbupdate = DatabaseUpdate()
api_logger = logger.Logger()
api_login = APILogin()


def generate_list(length, type):
    # Generate different possible param value for brute force
    lis = []
    if type == 'int':
        length = '%0' + str(length) + 'd'
        lis = [length % x for x in range(50)]
    elif type == 'str':
        for a in range(1, 50):
            lis += [''.join(
                random.choice(string.ascii_letters) for i in range(length))]
    return lis


def brute_force(url, method, headers, body, attack_params, scanid):
    attack_result = {}
    failed_set = ['exceed', 'captcha', 'too many', 'rate limit',
                  'Maximum login']
    if len(attack_params) == 1:
        # attack_params[0] is a first value from list Ex Pin, password
        param_value = body[
            attack_params[0]]  # param_value is a value of param. Example: 1234
        if type(param_value) == int:
            length = len(str(param_value))
            brute_list = generate_list(length, 'int')

        elif type(param_value) == str or type(param_value) == unicode:
            length = len(param_value)
            brute_list = generate_list(length, 'str')

        # Starting brute force attack.
        count = 0
        if brute_list is not None:
            for value in brute_list:
                # Mdofiying a json data and update the dictionary.
                # Example: {"Username":"test",password:"abc"}
                #          {"Username":"test",password:"def"}
                body[attack_params[0]] = value
                auth_type = get_value('config.property', 'login', 'auth_type')
                if auth_type == "cookie":
                    try:
                        del headers['Cookie']
                    except:
                        pass

                brute_request = req.api_request(url, method, headers, body)
                if brute_request is not None:
                    if count == 0:
                        http_len = len(brute_request.text)
                        count += count

            if len(brute_request.text) == http_len:
                if str(brute_request.status_code)[0] == '2' or \
                        str(brute_request.status_code)[0] == '4':
                    for failed_name in failed_set:
                        if failed_name in brute_request.text:
                            # Brute force protection detected :-(
                            result = False
                            break
                        else:
                            result = True

            if result is True:
                attack_result = {
                    "id": 7,
                    "scanid": scanid,
                    "url": url,
                    "alert": "Missing Rate limit",
                    "impact": "High",
                    "req_headers": headers,
                    "req_body": body,
                    "res_headers": brute_request.headers,
                    "res_body": brute_request.text

                }

            return attack_result


def rate_limit(url, method, headers, body, scanid=None):
    try:
        if method == "POST" or method == "PUT":
            if body:
                # Before we brute force, we need to find suspicious param
                # to attack.
                param_names = ['pin', 'password', 'cvv', 'pass', 'otp']
                attack_params = []
                for name in param_names:
                    for key, value in body.items():
                        if name.lower() == key.lower():
                            attack_params.append(name.lower())

                if attack_params:
                    attack_result = brute_force(url, method, headers, body,
                                                attack_params, scanid)
                    dbupdate.insert_record(attack_result)
    except:
        print "Failed to test rate limit"
