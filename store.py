#!/usr/bin/env python

import ConfigParser
from pymongo import MongoClient
import simplejson as json
import sys
import glob
import os

import logging
logger = logging.getLogger('vulnpryer.store')

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')


def _connect_to_datasctore():
    """ Connect to datastore """
    pass


def _load_json():
    """ Load JSON to selected data store"""
    pass


def _fetch_vuln_details():
    """ Fetch data on a particular vuln """
    pass


def _store_vuln_details():
    """ store data on a particular vuln """
    pass


if __name__ == "__main__":
    """Read in all the json files"""
    load_json("data_*.json")
