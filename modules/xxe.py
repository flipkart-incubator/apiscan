import socket
import requests
import threading
import time
import hashlib
import os
import utils.logs as logs

from utils.db import DatabaseUpdate

dbupdate = DatabaseUpdate()

# Dummy response
data = b'''\
HTTP/1.1 200 OK\r\n\
Connection: close\r\n\
Content-Type: text/html\r\n\
Content-Length: 6\r\n\
\r\n\
Hello!\
'''


class xxe_scan:
    def __init__(self):
        self.port = 1111
        self.host = socket.gethostbyname(socket.gethostname())

    def generate_hash(self):
        return hashlib.md5(str(time.time())).hexdigest()

    def start_server(self):
        self.s = socket.socket()
        try:
            self.s.bind((self.host, self.port))
            logs.logging.info("XXE: Server started.")
            return True
        except socket.error:
            logs.logging.info("XXE: Can't bind to port. "
                              "Port may be busy or check firewall setting.")

    def start_listening(self):
        global vulnerable
        vulnerable = False
        try:
            while True:
                # Wait for 5 seconds
                self.s.listen(5)
                self.conn, self.addr = self.s.accept()
                self.data = self.conn.recv(1024)
                if self.data and unique_id in self.data:
                    # External DTD is enable. URL is suspecious to XXE
                    self.conn.sendall(data)
                    vulnerable = True

            self.conn.close()

        except socket.error:
            print "[-]URL might not be vulnerable to XXE. " \
                  "We reccomend you to check it manually"
            self.conn.close()

    def fetch_xxe_payload(self):
        # Returns xxe payloads in list type
        payload_list = []
        if os.getcwd().split('/')[-1] == 'API':
            path = '../Payloads/xxe.txt'
        else:
            path = 'Payloads/xxe.txt'

        with open(path) as f:
            for line in f:
                if line:
                    payload_list.append(line.rstrip())

        return payload_list

    def send_request(self, url, method, temp_headers, xxe_payloads,
                     scanid=None):
        # Test if server accepts XML data
        sample_xml = """<?xml version="1.0" encoding="UTF-8"?>"""
        sample_xml += """<text>hello world</text>"""
        xml_request = requests.post(url, headers=temp_headers, data=sample_xml)
        if xml_request.status_code == 415:
            # Media type not supported.
            return
        global unique_id
        unique_id = self.generate_hash()
        host = "http://" + str(self.host) + ":" + str(
            self.port) + "/" + unique_id
        for payload in xxe_payloads:
            payload = payload.replace("{host}", host)
            xxe_request = requests.post(url,
                                        headers=temp_headers,
                                        data=payload)
            time.sleep(10)
            if vulnerable is True:
                print "[+]{0} is vulnerable to XML External Entity Attack"\
                    .format(url)
                attack_result = {"id": 14,
                                 "scanid": scanid,
                                 "url": url,
                                 "alert": "XML External Entity Attack",
                                 "impact": "High",
                                 "req_headers": temp_headers,
                                 "req_body": payload,
                                 "res_headers": xxe_request.headers,
                                 "res_body": xxe_request.text}
                dbupdate.insert_record(attack_result)
                break

    def xxe_test(self, url, method, headers, body, scanid=None):
        temp_headers = {}
        temp_headers.update(headers)
        xxe = xxe_scan()
        socketresult = xxe.start_server()
        if socketresult is True:
            t = threading.Thread(target=xxe.start_listening)
            t.daemon = True
            t.start()
            temp_headers['Content-Type'] = 'text/xml'
            xxe_payloads = self.fetch_xxe_payload()
            self.send_request(url, method, temp_headers, xxe_payloads, scanid)
