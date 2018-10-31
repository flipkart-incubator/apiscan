import json
import base64


class PostmanParser:
    api_lst = []

    def parse_json_file(self, json_file):
        with open(json_file) as data_file:
            json_data = json.loads(data_file.read())
        return json_data

    def postman_parser(self, postman_file):

        # Postman collection is a file in json format.
        # Convert the file to a json object.
        postman_data = self.parse_json_file(postman_file)

        # 'item' is a list of all the requests.
        # So if 'item' is not present, no point in continuing
        if "item" in postman_data:
            requests_collection = postman_data["item"]
        else:
            print " 'item' not found in the postman collection."
            return
        for each_request in requests_collection:
            api = {}
            if "request" in each_request:
                each_request = each_request["request"]
                if "url" in each_request:
                    # add the request only if the url is not empty
                    if each_request["url"] is not None:
                        api["url"] = each_request["url"]
                        api["method"] = ""
                        api["headers"] = {}
                        api["body"] = ""

                        if "method" in each_request:
                            api['method'] = each_request["method"]
                        if "body" in each_request:
                            if each_request["body"]:
                                if "raw" in each_request["body"]:
                                    # Body will be base64 encoding
                                    # of a raw string.
                                    api["body"] = base64.b64encode(
                                        bytes(each_request["body"]["raw"]),
                                        'utf-8')
                        if "header" in each_request:
                            headers = each_request["header"]
                            for each_header in headers:
                                key = each_header["key"]
                                value = each_header["value"]
                                api["headers"][key] = value
                        self.api_lst.append(api)
