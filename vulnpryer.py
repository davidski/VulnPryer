#!/usr/bin/env python

import argparse
from datetime import date, timedelta
from dateutil.parser import parse

# VulnDB components
from vulndb import query_vulndb
from mongo_loader import load_mongo, get_extract
from trl import get_trl, modify_trl, post_trl

# set default dates
to_date = date.today()
from_date = to_date + timedelta(days=-1)


def mkdate(datestr):
    """Coerce arguments into date type"""
    if not isinstance(datestr, date):
        return parse(datestr)
    else:
        return datestr

parser = argparse.ArgumentParser()
parser.add_argument('-e', '--enddate', type=mkdate, default=to_date,
                    help="Start date.")
parser.add_argument('-s', '--startdate', type=mkdate, default=from_date,
                    help="End date.")
args = parser.parse_args()

startstring = args.startdate
startstring = startstring.strftime("%Y-%m-%d")
endstring = args.enddate
endstring = endstring.strftime("%Y-%m-%d")

print "Range requested %s - %s" % (startstring, endstring)
query_vulndb(args.startdate, args.enddate)

print "Loading data into Mongo"
load_mongo('data_*.json')

print "Generating extract"
get_extract('/tmp/vulndb_export.csv')

print "Fetching RedSeal TRL"
get_trl('/tmp/trl.gz')

print "Generating modified TRL"
new_trl_path = modify_trl('/tmp/trl.gz')

print "Posting modified TRL to S3"
post_trl(new_trl_path)
