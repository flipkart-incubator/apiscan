import subprocess
import os
import time
import sys
import requests

sys.path.append('../')

from utils.config import get_value
from utils.logger import Logger

api_logger = Logger()


def get_config_value(name):
    # Return the value from config file. Ex Port, apikey
    config_value = get_value('config.property', 'Configuration', name)
    return config_value


def check_status(port):
    # Return the status of ZAP.
    try:
        api_url = "http://127.0.0.1:" + port
        api_status = requests.get(api_url)
    except:
        return False

    if api_status.status_code == 200:
        print "%s[+]Zap started successfully%s" % (api_logger.Y, api_logger.W)
        return True


def zap_start():
    port = get_config_value("zap_port")
    api_key = get_config_value("zap_apikey")
    apikey = 'api.key=' + api_key
    result = check_status(port)
    if result:
        # Zap is already running. No need to start it again.
        return result
    if os.getcwd().split('/')[-1] == 'API':
        os.chdir("../core/ZAP_2.7.0")
    else:
        os.chdir("core/ZAP_2.7.0")

    p = subprocess.Popen(
        ['java', '-jar', 'zap-2.7.0.jar', '-daemon', '-port', port, '-config',
         apikey], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(10)
    zap_status = check_status(port)
    print "cur dir", os.getcwd()
    os.chdir("../../")
    return zap_status
