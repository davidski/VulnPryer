#!/usr/bin/env python

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.utils import viewitems
# from builtins import *

from vulnpryer.config import read_config
from pymongo import MongoClient, errors
import csv
import simplejson as json
import sys
import glob
import logging
import os

logger = logging.getLogger('vulnpryer.shiploader')

config = read_config()
mongo_uri = config.get('Mongo', 'uri')
temp_directory = config.get('VulnDB', 'working_dir')
json_directory = config.get('VulnDB', 'json_dir')

# connect to our MongoDB instance
logger.debug("Mongo uri is: {}".format(mongo_uri))
client = MongoClient(mongo_uri)
db = client.vulndb
collection = db.osvdb
try:
    client.server_info()
except errors.ServerSelectionTimeoutError as err:
    logger.error("Failure connecting to Mongo at {}, {}"
                 .format(mongo_uri, err))
    raise

def _decode_list(data):
    rv = []
    for item in data:
        if isinstance(item, str):
            item = item.encode('utf-8')
        elif isinstance(item, list):
            item = _decode_list(item)
        elif isinstance(item, dict):
            item = _decode_dict(item)
            rv.append(item)
    return rv


def _decode_dict(data):
    rv = {}
    for (key, value) in viewitems(data):
        # if isinstance(key, str):
        #    key = key.decode('utf-8')
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        if isinstance(value, bytes):
            value = value.decode('utf-8')
        # elif isinstance(value, str):
        #    value = value.decode('utf-8')
        elif isinstance(value, list):
            value = _decode_list(value)
        elif isinstance(value, dict):
            value = _decode_dict(value)
        rv[key] = value
    return rv


def load_mongo(json_glob_pattern):
    """Load a pattern of JSON files to Mongo"""
    path_to_json = json_directory + json_glob_pattern
    logger.info("Looking for JSON files matching {}".format(path_to_json))
    for filename in sorted(glob.glob(path_to_json), key=os.path.getmtime):
        logger.info("Working on: {}".format(filename))
        json_data = open(filename).read()
        data = {}
        try:
            # auto-handling unicode object hook derived from
            # http://stackoverflow.com/questions/956867/how-to-get-string-
            # objects-instead-unicode-ones-from-json-in-python
            data = json.loads(json_data, object_hook=_decode_dict)
        except:
            logger.warning("{} Unexpected error: {}".format(sys.argv[0],
                           sys.exc_info()[1]))
        if data is None:
            continue
        for vulndb in data['results']:
            logger.debug(json.dumps(vulndb, sort_keys=True, indent=4 * ' '))
            vulndb['_id'] = vulndb['osvdb_id']
            osvdb_id = collection.save(vulndb)
            # osvdb_id = collection.insert(vulndb)
            logger.debug("Saved: {} with MongoDB id: {}".format(
                filename, osvdb_id))
    logger.info("Mapping OSVDB entries to CVE IDs")
    _map_osvdb_to_cve()
    logger.info("Marking deprecated VUulnDB entries")
    _mark_deprecated_entries()


def _map_osvdb_to_cve():
    """Add CVE_ID field to all OSVDB entries"""
    results = db.osvdb.aggregate([
        {"$unwind": "$ext_references"},
        {"$match": {"ext_references.type": "CVE ID"}},
        {"$project": {"CVE_ID": "$ext_references.value"}},
        {"$group": {"_id": "$_id", "CVE_ID": {"$addToSet": "$CVE_ID"}}}
    ])
    for entry in results:
        db.osvdb.update({"_id": entry['_id']},
                        {"$set": {"CVE_ID": entry['CVE_ID']}})
        logger.info("Adding CVEs to {}".format(entry['_id']))


def _mark_deprecated_entries():
    """Mark deprecated entries as such"""
    logger.info("Marking deprecated entries based on title.")
    db.osvdb.update(
        {'title': {'$regex': '^DEPRECA'}},
        {'$set': {'deprecated': True}},
        upsert=False, multi=True
    )


def _run_aggregation():
    """Set the classifications to a bogus array value if it's empty (size 0)
    this keeps the unwind from dropping empty classification documents
    alternate query based upon ext.references.type == 'CVE ID.'
    """
    results = []
    result_cursor = db.osvdb.aggregate([
        {"$unwind": "$CVE_ID"},
        {"$unwind": "$cvss_metrics"},
        {"$project": {"CVE_ID": 1, "ext_references": 1,
                      "cvss_score":
                          "$cvss_metrics.calculated_cvss_base_score",
                      "classifications": {"$cond": {
                          "if": {"$eq": [{"$size": "$classifications"}, 0]},
                          "then": ["bogus"],
                          "else": "$classifications"}}}},
        {"$unwind": "$classifications"},
        {"$unwind": "$ext_references"},
        {"$group": {
            "_id": {"_id": "$_id", "CVE_ID": {"$concat": ["CVE-", "$CVE_ID"]}},
            "public_exploit": {"$sum": {"$cond": [
                {"$eq": ["$classifications.name", "exploit_public"]}, 1, 0]}},
            "private_exploit": {"$sum": {"$cond": [
                {"$eq": ["$classifications.name", "exploit_private"]}, 1, 0]}},
            "cvss_score": {"$max": "$cvss_score"},
            "msp": {"$sum": {"$cond": [{"$eq": ["$ext_references.type",
                                                "Metasploit URL"]}, 1, 0]}},
            "edb": {"$sum": {"$cond": [{"$eq": ["$ext_references.type",
                                                "Exploit Database"]}, 1, 0]}},
            "network_vector": {"$sum": {"$cond": [{"$eq": [
                "$classifications.name", "location_remote"]}, 1, 0]}},
            "impact_integrity": {"$sum": {"$cond": [
                {"$eq": ["$classifications.name",
                         "impact_integrity"]}, 1, 0]}},
            "impact_confidential": {"$sum": {"$cond": [
                {"$eq": ["$classifications.name",
                         "impact_confidential"]}, 1, 0]}}}},
        {"$project": {"_id": 0, "OSVDB": "$_id._id",
                      "CVE_ID": "$_id.CVE_ID",
                      "public_exploit": 1, "private_exploit": 1,
                      "cvss_score": 1, "msp": 1, "edb": 1,
                      "network_vector": 1, "impact_integrity": 1,
                      "impact_confidentiality": "$impact_confidential"}}
    ], cursor={}
    )
    # comment out {"$match": {"network_vector": {"$gt": 0}}}

    for doc in result_cursor:
        results.append(doc)

    logger.info("There are {} entries in this aggregation.".format(
        len(results)))
    logger.debug("The headers are: {}".format(results[0].keys()))
    return results


def _calculate_mean_cvss():
    """Calculate the mean CVSS score across all known vulnerabilities"""
    results = []
    results_cursor = db.osvdb.aggregate([
        {"$unwind": "$cvss_metrics"},
        {"$group": {
            "_id": "null",
            "avgCVSS": {"$avg": "$cvss_metrics.calculated_cvss_base_score"}
        }}
    ])
    for doc in results_cursor:
        results.append(doc)

    logger.info("There are {} entries in this aggregation.".format(
        len(results)))
    logger.debug("The headers are: {}".format(results[0].keys()))
    try:
        avgCVSS = results[0]['avgCVSS']
    except:
        avgCVSS = None
    return avgCVSS


class _DictUnicodeProxy(object):
    """Create helper function for writing unicode to CSV"""

    def __init__(self, d):
        self.d = d

    def __iter__(self):
        return self.d.__iter__()

    def get(self, item, default=None):
        i = self.d.get(item, default)
        if isinstance(i, list):
            i = i[0]
        if isinstance(i, str):
            return i.encode('utf-8')
        return i


def _write_vulndb(results, filename):
    """Dump output to CSV"""
    if sys.version_info[0] < 3:
        csvfile = open(filename, 'wb')
    else:
        csvfile = open(filename, 'w', newline='')

    # headers = ['CVE_ID', 'OSVDB', 'public_exploit', 'private_exploit',
    # 'cvss_score', 'msp', 'edb', 'network_vector', 'impact_integrity',
    # 'impact_confidentiality', 'network_vector']
    headers = results[0].keys()
    csvwriter = csv.DictWriter(csvfile, fieldnames=headers)
    csvwriter.writeheader()
    for result in results:
        csvwriter.writerow(_DictUnicodeProxy(result))

    csvfile.close()


def get_extract(extract_file):
    results = _run_aggregation()
    _write_vulndb(results, extract_file)


if __name__ == "__main__":
    """Read in all the json files"""
    load_mongo("data_*.json")
    get_extract(temp_directory + 'vulndb_export.csv')
