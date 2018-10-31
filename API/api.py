import ast
import os
import sys
import hashlib
import time
import json
import threading
import logging

sys.path.append('../')

from flask import render_template, send_from_directory
from flask import request
from flask import Flask
from flask import jsonify
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
from utils.vulnerabilities import alerts

if os.getcwd().split('/')[-1] == 'API':
    from astra import scan_single_api

app = Flask(__name__, template_folder='../Dashboard/templates',
            static_folder='../Dashboard/static')


class ServerThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        app.run(host='0.0.0.0', port=8094)


# Mongo DB connection
maxSevSelDelay = 1
try:
    mongo_host = 'localhost'
    mongo_port = 27017

    if 'MONGO_PORT_27017_TCP_ADDR' in os.environ:
        mongo_host = os.environ['MONGO_PORT_27017_TCP_ADDR']

    if 'MONGO_PORT_27017_TCP_PORT' in os.environ:
        mongo_port = int(os.environ['MONGO_PORT_27017_TCP_PORT'])

    client = MongoClient(mongo_host, mongo_port,
                         serverSelectionTimeoutMS=maxSevSelDelay)
    client.server_info()

except ServerSelectionTimeoutError as err:
    exit("Failed to connect to MongoDB.")

global db
db = client.apiscan

""" Start scan API  """


def generate_hash():
    # Return md5 hash value of current timestmap
    scanid = hashlib.md5(str(time.time())).hexdigest()
    return scanid


def xss_filter(data):
    data = str(data)
    # Filter special chars to prevent XSS
    filterd_data = data.replace("<", "&lt;").replace(">", "&gt;")
    try:
        filterd_data = ast.literal_eval(filterd_data)
    except:
        pass

    return filterd_data


# Start the scan and returns the message
@app.route('/scan/', methods=['POST'])
def start_scan():
    scanid = generate_hash()
    content = request.get_json()
    try:
        name = content['appname']
        url = str(content['url'])
        headers = str(content['headers'])
        body = str(content['body'])
        method = content['method']
        api = "Y"
        scan_status = scan_single_api(url, method, headers, body, api, scanid)
        if scan_status is True:
            # Success
            msg = {"status": scanid}
            try:
                db.scanids.insert({"scanid": scanid, "name": name, "url": url})
            except:
                print "Failed to update DB"
        else:
            msg = {"status": "Failed"}

    except:
        msg = {"status": "Failed"}

    return jsonify(msg)


""" Fetch ScanID API  """


def check_scan_status(data):
    # Return the Scan status
    total_scan = data['total_scan']
    count = 0
    for key, value in data.items():
        if value == 'Y' or value == 'y':
            count += 1

    if total_scan == count:
        return "Completed"
    else:
        return "In progress"


@app.route('/scan/scanids/', methods=['GET'])
def fetch_scanids():
    scanids = []
    records = db.scanids.find({})
    if records:
        for data in records:
            data.pop('_id')
            try:
                data = ast.literal_eval(json.dumps(data))
                scan_status = check_scan_status(data)
                if data['scanid']:
                    if data['scanid'] not in scanids:
                        url = xss_filter(data['url'])
                        scanids.append({"scanid": data['scanid'],
                                        "name": xss_filter(data['name']),
                                        "url": url,
                                        "scan_status": scan_status})
            except:
                pass

        return jsonify(scanids)


""" Alerts API  """


# Returns vulnerbilities identified by tool
def fetch_records(scanid):
    # Return alerts identified by the tool
    vul_list = []
    records = db.vulnerabilities.find({"scanid": scanid})
    if records:
        for data in records:
            if data['req_body'] is None:
                data['req_body'] = "NA"

            data.pop('_id')
            try:
                data = ast.literal_eval(json.dumps(data))
            except Exception as e:
                print "Falied to parse", e

            try:
                if data['id'] == "NA":
                    all_data = {'url': data['url'], 'impact': data['impact'],
                                'name': data['name'],
                                'req_headers': data['req_headers'],
                                'req_body': data['req_body'],
                                'res_headers': data['res_headers'],
                                'res_body': data['res_body'],
                                'Description': data['Description'],
                                'remediation': data['remediation']}
                    vul_list.append(all_data)

                if data['id']:
                    for vul in alerts:
                        if data['id'] == vul['id']:
                            all_data = {
                                'url': xss_filter(data['url']),
                                'impact': data['impact'],
                                'name': xss_filter(data['alert']),
                                'req_headers': data['req_headers'],
                                'req_body': xss_filter(data['req_body']),
                                'res_headers': xss_filter(data['res_headers']),
                                'res_body': xss_filter(data['res_body']),
                                'Description': vul['Description'],
                                'remediation': vul['remediation']
                            }
                            vul_list.append(all_data)
                            break

            except:
                pass

        return vul_list


@app.route('/alerts/<scanid>', methods=['GET'])
def return_alerts(scanid):
    result = fetch_records(scanid)
    resp = jsonify(result)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


""" Dashboard """


@app.route('/', defaults={'page': 'scan.html'})
@app.route('/<page>')
def view_dashboard(page):
    return render_template('{}'.format(page))


def start_server():
    app.run(host='0.0.0.0', port=8094)


# if __name__ == "__main__":

def main():
    if os.getcwd().split('/')[-1] == 'API':
        start_server()
    else:
        thread = ServerThread()
        thread.daemon = True
        thread.start()


@app.route('/robots.txt', methods=['GET'])
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


main()
