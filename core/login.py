import requests
import zapscan
import parsers
import json
import base64
import sys
import utils.logs as logs

from utils.config import update_value, get_value


class APILogin:

    def __init__(self):
        self.api_logger = zapscan.Logger()
        self.parse_data = parsers.PostmanParser()

    def fetch_logintoken(self, url, method, headers, body=None, relogin=None):
        if method.upper() == "GET":
            login_request = requests.get(url, headers=headers)
        elif method.upper() == "POST":
            login_request = requests.post(url, headers=headers, json=body)
            logs.logging.info("HTTP response of login API : %s %s %s",
                              login_request.status_code, headers, body)
        else:
            print
            "[-]Invalid request"
            sys.exit(1)

        try:
            login_response = json.loads(login_request.text)
        except:
            pass

        if relogin is not None:
            print(
                "Session fixation attack won't be tested since it failed to "
                "re-login."
            )
            return

        auth_names = get_value('config.property', 'login', 'auth_names')
        auth_type = get_value('config.property', 'login', 'auth_type')
        auth_names = auth_names.split(',')
        # auth_header = get_value('config.property','login','auth_header')

        # Auth types:
        # 1. Cookie
        # 2. Basic
        # 3. Oauth
        auth_status = False
        if auth_type == 'cookie':
            if login_request.headers['Set-Cookie']:
                auth_cookie = {'cookie': login_request.headers['Set-Cookie']}
                print
                "[+]Login successful"
                update_value('login', 'auth_success', 'Y')
                update_value('login', 'cookie', auth_cookie)
                auth_status = True

        # Basic and oauth auth type code will come here(yet to develop).
        else:
            for auth_name in auth_names:
                if auth_name in login_response:
                    auth_success_token = login_response[auth_name]
                    print
                    "[+]Login successful"
                    update_value('login', 'auth_success', 'Y')
                    update_value('login', 'auth_success_param', auth_name)
                    update_value('login', 'auth_success_token',
                                 auth_success_token)
                    auth_status = True
                    break

        if not auth_status:
            login_response = raw_input(
                "Failed to login. Do you want to continue scanning without "
                "cookie(y/n),"
                + self.api_logger.G + url + ': ' + self.api_logger.W)
            if login_response == 'Y' or login_response == 'y':
                return
            elif login_response == 'n' or login_response == 'N':
                sys.exit(1)

    def create_urllist(self, collection_data):
        url_list = []
        for data in collection_data:
            try:
                url = data['url']['raw']
                url_list.append(url)
            except:
                url = data['url']
                url_list.append(url)
        return url_list

    def verify_logout(self, collection_data, api_url):
        if api_url is not None:
            for data in collection_data:
                if data['url'] == api_url:
                    url, method, headers, body = (data['url'],
                                                  data['method'],
                                                  data['headers'],
                                                  data['body'])
                    logout_data = {
                        'logouturl': url,
                        'logoutmethod': method,
                        'logoutheaders': headers,
                        'logoutbody': body,
                        'logoutresult': 'Y'}
                    break

            for key, value in logout_data.items():
                update_value("logout", key, value)
            return
        else:
            print
            "Failed"

    def auth_verify(self, collection_data, api):
        login_names = ['login', 'signin', 'authenticate']
        logout_names = ['logout', 'signout']
        if api == 'login':
            api_types = login_names
        elif api == 'logout':
            api_types = logout_names

        url_list = self.create_urllist(collection_data)

        for url in url_list:
            for name in api_types:
                if name in url:
                    if api == 'login':
                        result = raw_input(
                            "Is it a correct login URL(y/n)," +
                            self.api_logger.G + url + ': ' + self.api_logger.W)
                    elif api == 'logout':
                        result = raw_input(
                            "Is it a correct logout URL(y/n)," +
                            self.api_logger.G + url + ': ' + self.api_logger.W)

                    if result == 'y' or result == 'Y':
                        return url, api
                    else:
                        return None, None
        return None, None

    def verify_login(self, collection_data):
        api_url, api_type = self.auth_verify(collection_data, 'login')
        logs.logging.info("API URL for login is : %s", api_url)
        if api_url is None:
            auth_response = raw_input(
                self.api_logger.Y +
                "[-]Failed to detect login url. Do you want to continue "
                "without authentication?(y/n):" +
                self.api_logger.W)
            if auth_response == 'y' or auth_response == 'Y':
                return
            else:
                sys.exit(1)

        for data in collection_data:
            if data['url'] == api_url:
                url, method, headers, body = data['url'], data['method'],\
                                             data['headers'], data['body']
                if api_type == 'login':
                    if body:
                        body = json.loads(base64.b64decode(body))
                        login_token = self.fetch_logintoken(url,
                                                            method,
                                                            headers,
                                                            body)
                    else:
                        login_token = self.fetch_logintoken(url,
                                                            method,
                                                            headers)

                    if login_token is True:
                        logs.logging.info("Login successfully : %s", url)
                        # calling auth_verify function to fetch logout request
                        logout_url, api_type = self.auth_verify(
                            collection_data,
                            "logout")
                        self.verify_logout(collection_data, logout_url)
                        auth_data = {'loginurl': url,
                                     'loginmethod': method,
                                     'loginheaders': headers,
                                     'loginbody': body,
                                     'loginresult': 'Y'}
                        for key, value in auth_data.items():
                            update_value("login", key, value)
                        return

    def parse_logindata(self, loginurl):
        for data in self.parse_data.api_lst:
            if loginurl == data['url']:
                headers, method, body = data['headers'], data['method'], ''
                if data['body'] != '':
                    body = json.loads(base64.b64decode(data['body']))
                return loginurl, headers, method, body
