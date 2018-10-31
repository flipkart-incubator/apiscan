import utils.logs as logs

try:
    import requests

    requests.packages.urllib3.disable_warnings()
except:
    print "[-]Failed to import requests module"


def api_request(url, method, headers, body=None):
    try:
        if method.upper() == "GET":
            auth_request = requests.get(url, headers=headers,
                                        allow_redirects=False, verify=False)
        elif method.upper() == "POST":
            auth_request = requests.post(url, headers=headers, json=body,
                                         allow_redirects=False, verify=False)
        elif method.upper() == "PUT":
            auth_request = requests.put(url, headers=headers, data=body,
                                        allow_redirects=False, verify=False)
        elif method.upper() == "OPTIONS":
            auth_request = requests.options(url, headers=headers, verify=False)
        return auth_request

    except Exception as e:
        logs.logging.error("Exception from sendrequest %s", e)
