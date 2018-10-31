from pymongo import MongoClient
import os


class DatabaseUpdate:
    def __init__(self):
        # Mongo DB connection
        mongo_host = 'localhost'
        mongo_port = 27017

        maxSevSelDelay = 1

        if 'MONGO_PORT_27017_TCP_ADDR' in os.environ:
            mongo_host = os.environ['MONGO_PORT_27017_TCP_ADDR']

        if 'MONGO_PORT_27017_TCP_PORT' in os.environ:
            mongo_port = int(os.environ['MONGO_PORT_27017_TCP_PORT'])

        self.client = MongoClient(mongo_host, mongo_port,
                                  serverSelectionTimeoutMS=maxSevSelDelay)
        self.db = self.client.apiscan

    def fetch_records(self):
        records = self.db.vulnerbilities.find({})
        if records:
            for data in records:
                data.pop('_id')
                print data

    def insert_record(self, data):
        try:
            self.db.vulnerabilities.insert(data)
        except Exception as e:
            raise e

    def update_record(self, find, update):
        try:
            self.db.vulnerabilities.update(find, update)
        except Exception as e:
            raise e

    def update_scan_record(self, find, update):
        try:
            self.db.scanids.update(find, update)
        except Exception as e:
            raise e
