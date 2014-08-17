#!/usr/bin/env python

import ConfigParser
from pymongo import MongoClient
import csv
import simplejson as json
import sys
import glob
import logging

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

mongo_host      = config.get('Mongo', 'hostname')
temp_directory  = config.get('VulnDB', 'working_dir')
json_directory  = config.get('VulnDB', 'json_dir')

#connect to our MongoDB instance,
client = MongoClient(host = mongo_host)
db = client.vulndb
collection = db.osvdb

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, unicode):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
            rv.append(item)
    return rv

def _decode_dict(data):
    rv = {}
    for key, value in data.iteritems():
        if isinstance(key, unicode):
           key = key.encode('utf-8')
        if isinstance(value, unicode):
           value = value.encode('utf-8')
        elif isinstance(value, list):
           value = _decode_list(value)
        elif isinstance(value, dict):
           value = _decode_dict(value)
        rv[key] = value
    return rv

## load a pattern of JSON files to Mongo
def load_mongo(json_glob_pattern):
    path_to_json = json_directory + json_glob_pattern
    for filename in glob.glob(path_to_json):
        logging.debug("Wokring on " + filename)
        json_data = open(filename).read()
        try:
            #auto-handling unicode object hook derived from
            #http://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-unicode-ones-from-json-in-python
            data = json.loads(json_data, object_hook = _decode_dict)
        except:
            print sys.argv[0], " Unexpected error:", sys.exc_info()[1]
        for vulndb in data['results']:
            logging.debug(json.dumps(vulndb, sort_keys=True, indent=4 * ' '))
            vulndb['_id'] = vulndb['osvdb_id']
            osvdb_id = collection.save(vulndb)
        #osvdb_id = collection.insert(vulndb)
        logging.info("Saved: ", filename, " with MongoDB id: ", osvdb_id)

## Run the Aggregation Query
def _run_aggregation():
    """Set the classifications to a bogus array value if it's empty (size 0)
    this keeps the unwind from dropping empty classification documents
    alternate query based upon ext.references.type == 'CVE ID.'
    """
    results = db.osvdb.aggregate([
        { "$project": { "ext_references": 1,
            "classifications": {
                "$cond": {
                    "if": { "$eq": [{"$size": "$classifications"}, 0] },
                    "then": ["bogus"],
                    "else": "$classifications" } } } },
        { "$unwind": "$ext_references" },
        { "$match": { "ext_references.type": 'CVE ID' } },
        { "$unwind": "$classifications" },
        { "$group": {
            "_id": {"_id": "$_id", "CVE_ID": { "$concat":
                [ "CVE-", "$ext_references.value"] }},
            "public_exploit": { "$sum": { "$cond": [
                { "$eq": [ "$classifications.name", "exploit_public" ] }, 1, 0 ]}},
            "private_exploit": { "$sum": { "$cond": [
                { "$eq": [ "$classifications.name", "exploit_private" ] }, 1, 0 ]}}
        }},
        { "$project": { "_id": 0, "OSVDB": "$_id._id", "CVE_ID": "$_id.CVE_ID", "public_exploit": 1, "private_exploit": 1 } }
    ])

    logging.info("There are {} entries in this aggregation.".format(len(results['result'])))
    #logging.debug("The headers are: " + results['result'][0].keys())
    return results

## Create helper function for writing unicode to CSV
class _DictUnicodeProxy(object):
    def __init__(self, d):
        self.d = d
    def __iter__(self):
        return self.d.__iter__()
    def get(self, item, default=None):
        i = self.d.get(item, default)
        if isinstance(i, list):
            i = i[0]
        if isinstance(i, unicode):
            return i.encode('utf-8')
        return i

## Dump output to CSV
def _write_vulndb(results, filename):
    csvfile = open(filename, 'wb')

    headers = ['CVE_ID', 'OSVDB', 'public_exploit', 'private_exploit']
    csvwriter = csv.DictWriter(csvfile, fieldnames=headers)
    csvwriter.writeheader()
    for result in results['result']:
        csvwriter.writerow(_DictUnicodeProxy(result))

    csvfile.close()

def get_extract(extract_file):
    results = _run_aggregation()
    _write_vulndb(results, extract_file)

if __name__ == "__main__":
    """Read in all the json files"""
    load_mongo("data_*.json")
    get_extract(temp_directory + 'vulndb_export.csv')