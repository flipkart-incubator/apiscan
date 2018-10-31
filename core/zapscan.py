__author__ = 'Sagar Popat'

import requests
import sys
import argparse
import urllib
import json
import time
import signal
import socket
import ast
import urllib
import sys
import utils.logs as logs

sys.path.append('../')

from utils.logger import *
from utils.config import *
from utils.db import DatabaseUpdate

try:
    import requests

    requests.packages.urllib3.disable_warnings()
except:
    print "[-]Failed to import requests module"


class zap_scan:

    def __init__(self):
        ''' Set the proxy ip, port and Apitoken of OWASP ZAP '''
        self.api_logger = Logger()
        self.dbupdate = DatabaseUpdate()
        self.ip = get_value('config.property', 'Configuration', 'ZAP_ip')
        self.port = get_value('config.property', 'Configuration', 'ZAP_port')
        self.proxy = {"http": "http://" + self.ip + ":" + self.port,
                      "https": "http://" + self.ip + ":" + self.port}
        self.apitoken = get_value('config.property', 'Configuration',
                                  'ZAP_apikey')
        self.zap_url = 'http://' + self.ip + ':' + str(self.port)

    def generate_report(self):
        zap_report = '{0}/OTHER/core/other/htmlreport/' \
                     '?apikey={1}&formMethod=GET'\
            .format(self.zap_url, self.apitoken)
        generate_report = requests.get(zap_report)
        try:
            write_report = open('report.html', 'w')
            write_report.write(generate_report.text)
            write_report.close()
            return True
        except e:
            return False

    def check_scanstatus(self, scan_id):
        scan_status = '{0}/JSON/ascan/view/status/' \
                      '?zapapiformat=JSON&apikey={1}' \
                      '&formMethod=GET&scanId={2}'\
            .format(self.zap_url, self.apitoken, scan_id)
        status = requests.get(scan_status)
        try:
            status = json.loads(status.text)['status']
            return status
        except Exception as e:
            raise e

    def update_db(self, scanid, url, alert, impact, description, solution,
                  messageId):
        """ This function gathers all the info of alert and updates the DB """
        message_url = '{0}/JSON/core/view/message/?zapapiformat=JSON' \
                      '&apikey={1}&formMethod=GET&id={2}'\
            .format(self.zap_url, self.apitoken, messageId)
        message_req = requests.get(message_url)
        message_data = json.loads(message_req.text)
        req_headers, req_body, res_headers, res_body = (
            message_data['message']['requestHeader'],
            message_data['message']['requestBody'],
            message_data['message']['responseHeader'],
            message_data['message']['responseBody']
        )
        attack_result = {"id": "NA", "scanid": scanid, "url": url,
                         "name": alert, "impact": impact,
                         "req_headers": req_headers, "req_body": req_body,
                         "res_headers": res_headers, "res_body": res_body,
                         "Description": description, "remediation": solution}
        self.dbupdate.insert_record(attack_result)

    def check_scanalerts(self, url, scan_id, scanid):
        scan_alerts = '{0}/JSON/core/view/alerts/?zapapiformat=JSON' \
                      '&apikey={1}&formMethod=GET&baseurl={2}&start=' \
                      '&count='.format(self.zap_url,
                                       self.apitoken,
                                       url)
        alert_id = 0
        while True:
            time.sleep(10)
            scan_status = self.check_scanstatus(scan_id)
            if int(scan_status) == 100:
                break
            else:
                alerts = requests.get(scan_alerts)
                zap_alerts = json.loads(alerts.text)
                try:
                    url = zap_alerts['alerts'][alert_id]['url']
                    alert = zap_alerts['alerts'][alert_id]['alert']
                    messageId = zap_alerts['alerts'][alert_id]['messageId']
                    impact = zap_alerts['alerts'][alert_id]['risk']
                    description = zap_alerts['alerts'][alert_id]['description']
                    solution = zap_alerts['alerts'][alert_id]['solution']
                    print "%s[+]{0} is vulnerable to {1}%s".format(url,
                                                                   alert) % (
                              self.api_logger.G, self.api_logger.W)
                    try:
                        self.update_db(scanid, url, alert, impact, description,
                                       solution, messageId)
                    except Exception as e:
                        logs.logging.info("Failed to update in db : %s", e)

                    alert_id = alert_id + 1
                except:
                    pass

    def start_scan(self, url, method, Headers=None, data=None, scanid=None):
        try:
            data = json.dumps(data)
            data = data.replace('\\"', "'")
        except:
            pass
        try:
            cookies = get_value('config.property', 'login', 'auth')
            cookies = ast.literal_eval(cookies)
            if cookies is None or '':
                cookies = ''
        except:
            cookies = ''

        if method.upper() == 'GET':
            try:
                access_url = requests.get(url, headers=Headers,
                                          proxies=self.proxy, cookies=cookies)
            except requests.exceptions.RequestException as e:
                print e

        elif method.upper() == 'POST':
            try:
                access_url = requests.post(url, headers=Headers, data=data,
                                           proxies=self.proxy, cookies=cookies,
                                           verify=False)
            except requests.exceptions.RequestException as e:
                return

        elif method.upper() == 'PUT':
            try:
                access_url = requests.put(url, headers=Headers, data=data,
                                          proxies=self.proxy)
            except requests.exceptions.RequestException as e:
                return

        ''' Check if URL is now present at scanning tree of ZAP.
            If it's not present then something is wrong with access_url
        '''

        view_urls = '{0}/JSON/core/view/urls/?zapapiformat=JSON' \
                    '&formMethod=GET&apikey={1}'.format(self.zap_url,
                                                        self.apitoken)
        view_urls = requests.get(view_urls)
        scantree_urls = json.loads(view_urls.text)
        if url or url + '/' in scantree_urls['urls']:
            data = "'" + data + "'"
            if method.upper() == 'GET':
                if '&' in url:
                    url = url.replace('&', '%26')
                active_scan = '{0}/JSON/ascan/action/scan/?zapapiformat=JSON' \
                              '&url={1}&recurse=False&inScopeOnly=False' \
                              '&scanPolicyName=&method={2}&postData=' \
                              '&apikey={3}'.format(self.zap_url,
                                                   url,
                                                   method,
                                                   self.apitoken)
            else:
                active_scan = '{0}/JSON/ascan/action/scan/' \
                              '?zapapiformat=JSON&url={1}&recurse=False' \
                              '&inScopeOnly=False&scanPolicyName=' \
                              '&method={2}&postData={3}' \
                              '&apikey={4}'.format(self.zap_url,
                                                   url,
                                                   method,
                                                   urllib.quote(data),
                                                   self.apitoken)
            start_ascan = requests.get(active_scan)
            try:
                scan_id = json.loads(start_ascan.text)['scan']
                if int(scan_id) >= 0:
                    print "[+]Active Scan Started Successfully"
                    self.check_scanalerts(url, scan_id, scanid)
            except:
                pass
