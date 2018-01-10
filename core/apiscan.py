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

from utils.logger import *
from utils.config import *
from utils.db import Database_update

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except:
    print "[-]Failed to import requests module"


class zap_scan:

    def __init__(self):
        ''' Set the proxy ip, port and Apitoken of OWASP ZAP '''
        self.api_logger = logger()
        self.dbupdate = Database_update()
        self.ip = get_value('Configuration','ZAP_ip')
        self.port = get_value('Configuration','ZAP_port')
        self.proxy = {"http" : "http://"+self.ip+":"+self.port, "https" : "http://"+self.ip+":"+self.port}
        self.apitoken = get_value('Configuration','ZAP_apikey')
        self.zap_url = 'http://'+self.ip+':'+str(self.port)

    def generate_report(self):
        zap_report = '{0}/OTHER/core/other/htmlreport/?apikey={1}&formMethod=GET'.format(self.zap_url,self.apitoken)
        generate_report = requests.get(zap_report)
        try:
            write_report = open('report.html', 'w')
            write_report.write(generate_report.text)
            write_report.close()
            return True
        except e:
            return False

    def check_scanstatus(self,scan_id):
        scan_status = '{0}/JSON/ascan/view/status/?zapapiformat=JSON&apikey={1}&formMethod=GET&scanId={2}'.format(self.zap_url,self.apitoken,scan_id)
        status = requests.get(scan_status)
        try:
            status = json.loads(status.text)['status']
            return status
        except Exception as e:
            raise e

    def check_scanalerts(self,url,scan_id):
        scan_alerts = '{0}/JSON/core/view/alerts/?zapapiformat=JSON&apikey={1}&formMethod=GET&baseurl={2}&start=&count='.format(self.zap_url,self.apitoken,url)
        alert_id = 0
        while True:
            print alert_id
            print "alert id is",alert_id
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
                    print "%s[+]{0} is vulnerable to {1}%s".format(url,alert)% (self.api_logger.G, self.api_logger.W)
                    #self.dbupdate.insert_record({"url" : url, "alert" : alert})
                    self.dbupdate.insert_record({"url" : url, "alert" : alert})
                    alert_id = alert_id + 1
                except:
                    pass
          
    def start_scan(self,url,method,Headers=None,data=None):
        print "inside scan"
        data = json.dumps(data)
        data = data.replace('\\"',"'")
        cookies = get_value('login','auth')
        cookies = ast.literal_eval(cookies)
        if cookies is None or '':
            cookies = ''

        if method.upper() == 'GET':
            try:
                access_url = requests.get(url,headers=Headers,proxies=self.proxy,cookies=cookies)
            except requests.exceptions.RequestException as e:
                print e
                return

        elif method.upper() == 'POST':
            try:
                access_url = requests.post(url,headers=Headers,data=data,proxies=self.proxy,cookies=cookies,verify=False)
                print url
                print "Method", method
                print "status",access_url.status_code
                print access_url.text
            except requests.exceptions.RequestException as e:
                print e
                return

        elif method.upper() == 'PUT':
            try:
                access_url = requests.put(url,headers=Headers,data=data,proxies=self.proxy)
            except requests.exceptions.RequestException as e:
                print e
                return
        
        ''' Check if URL is now present at scanning tree of ZAP.
            If it's not present then something is wrong with access_url
        '''

        view_urls = '{0}/JSON/core/view/urls/?zapapiformat=JSON&formMethod=GET&apikey={1}'.format(self.zap_url,self.apitoken)
        view_urls = requests.get(view_urls)
        scantree_urls = json.loads(view_urls.text)
        if url or url+'/' in scantree_urls['urls']:
                data = "'"+data+"'"
                if method.upper() == 'GET':
                    if '&' in url:
                        url = url.replace('&','%26')
                    active_scan = '{0}/JSON/ascan/action/scan/?zapapiformat=JSON&url={1}&recurse=False&inScopeOnly=False&scanPolicyName=&method={2}&postData=&apikey={3}'.format(self.zap_url,url,method,self.apitoken)
                else:
                    active_scan = '{0}/JSON/ascan/action/scan/?zapapiformat=JSON&url={1}&recurse=False&inScopeOnly=False&scanPolicyName=&method={2}&postData={3}&apikey={4}'.format(self.zap_url,url,method,urllib.quote(data),self.apitoken)
                start_ascan = requests.get(active_scan)
                try:
                    scan_id = json.loads(start_ascan.text)['scan']
                    if int(scan_id) >= 0:
                        print "[+]Active Scan Started Successfully"
                        self.check_scanalerts(url,scan_id)              
                except:
                    pass
 