import time
import requests
import json
import sendrequest as req
import utils.logs as logs
import subprocess

from utils.logger import Logger
from utils.db import DatabaseUpdate

dbupdate = DatabaseUpdate()
api_logger = Logger()

base_url = "http://127.0.0.1:8775"
api_header = {'Content-Type': 'application/json'}


def get_new_task_id():
    # Create a new task for scan
    new_task_url = base_url + "/task/new"
    new_task = req.api_request(new_task_url, "GET", api_header)
    if new_task.status_code == 200:
        return json.loads(new_task.text)['taskid']


def set_options_list(url, method, headers, body, task_id):
    # Setting up url,headers, body for scan
    options_set_url = base_url + "/option/" + task_id + "/set"
    data = {}
    data['url'], data['method'], data['headers'] = url, method, headers
    if method.upper() == 'POST' or method.upper() == 'PUT':
        data['data'] = body
    options_list = req.api_request(options_set_url, "POST", api_header, data)
    if options_list.status_code == 200:
        return json.loads(options_list.text)['success']


def start_scan(task_id):
    # Starting a new scan
    data = {}
    scan_start_url = base_url + "/scan/" + task_id + "/start"
    scan_start_resp = req.api_request(scan_start_url, "POST", api_header, data)
    if scan_start_resp.status_code == 200:
        return json.loads(scan_start_resp.text)['success']
        time.sleep(10)


def delete_task(task_id):
    # Delete the task once the scan is completed
    delete_task_url = base_url + "/task/" + task_id + "/delete"
    delete_task_req = req.api_request(delete_task_url, "GET", api_header)
    if delete_task_req.status_code == 200:
        return json.loads(delete_task_req.text)['success']


def show_scan_data(task_id):
    scan_data_url = base_url + "/scan/" + task_id + "/data"
    scan_start_resp = req.api_request(scan_data_url, "GET", api_header)
    global scan_data
    scan_data = json.loads(scan_start_resp.text)['data']
    if scan_data:
        logs.logging.info("API is vulnerable to sql injection")
        return True
    else:
        logs.logging.info("API is not vulnerable to sql injection")
        return False


def scan_status(task_id):
    # This function deals checking scan status
    # and also check for vulnerability.
    status_url = base_url + "/scan/" + task_id + "/status"
    while True:
        status_url_resp = req.api_request(status_url, "GET", api_header)
        if json.loads(status_url_resp.text)['status'] == "terminated":
            result = show_scan_data(task_id)
            return result
        else:
            # Wait for 10 second and check the status again
            time.sleep(10)


def sqlmap_start():
    try:
        p = subprocess.Popen(["pip", "show", "sqlmap"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        if out:
            location = out[out.find('Location:') + 10:]
            sqlmap_path = location[
                          :location.find('\n')] + '/sqlmap/sqlmapapi.py'
            if sqlmap_path:
                # Sqlmap is found
                start_sqlmap = subprocess.Popen(['python', sqlmap_path, '-s'],
                                                stdout=subprocess.PIPE)
                time.sleep(5)
                while True:
                    line = start_sqlmap.stdout.readline()
                    if "Admin" in line:
                        logs.logging.info("sqlmap is started")
                        return True

    except:
        logs.logging.info("Failed to start sqlmap")
        return


def sqlmap_status():
    # Check if sqlmap is running or not.
    try:
        sqlmap_status = requests.get(base_url)
        if 'Nothing here' in sqlmap_status.text:
            logs.logging.info("Sqlmap is running")
            return True
    except:
        result = sqlmap_start()
        return result


def sqli_check(url, method, headers, body, scanid=None):
    # Main function for sql injection
    result = sqlmap_status()
    if result is True:
        taskid = get_new_task_id()
        if taskid:
            # Taskid is created.
            set_option_status = set_options_list(url, method, headers, body,
                                                 taskid)
            if set_option_status is True:
                # Everything is set to start the scan
                start_scan_result = start_scan(taskid)
                if start_scan_result is True:
                    logs.logging.info("SQLi - Scan started.")
                    result = scan_status(taskid)
                    if result is True:
                        # API is vulnerable
                        print "%s[+]{0} is vulnerable to SQL injection%s"\
                                  .format(url) % (api_logger.R, api_logger.W)
                        attack_result = {"id": 10,
                                         "scanid": scanid,
                                         "url": url,
                                         "alert": "SQL injection",
                                         "impact": "High",
                                         "req_headers": headers,
                                         "req_body": body,
                                         "res_headers": "NA",
                                         "res_body": "NA",
                                         "log": scan_data}
                        dbupdate.insert_record(attack_result)

        else:
            logs.logging.info("Sqli - Failed to create a task.")

        task_result = delete_task(taskid)
        if task_result is True:
            # Task deleted successfully
            logs.logging.info("SQLi - Task deleted: %s", taskid)
