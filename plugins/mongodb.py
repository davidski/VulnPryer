#!/usr/bin/env python

import VulnPryerPluginClass as plugintypes

from pymongo import MongoClient
import simplejson as json
import sys
import glob
import os

import logging
logger = logging.getLogger('vulnpryer.store')


class IMongoDB(plugintypes.IStorePlugin):
    """MongoDB storage plugin"""

    def connect_to_datastore(self):
        """Connect to datastore."""
        pass

    def load_json(self):
        """Load JSON to selected data store."""
        pass

    def fetch_vuln_details(self):
        """Fetch data on a particular vuln."""
        pass

    def store_vuln_details(self):
        """Store data on a particular vuln."""
        pass

if __name__ == "__main__":
    """Read in all the json files"""
    load_json("data_*.json")
