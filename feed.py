#!/usr/bin/env python

from restkit import OAuthFilter, request
import simplejson as json
import oauth2
from datetime import date, timedelta
import logging
import ConfigParser

logger = logging.getLogger('vulnpryer.feed')

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

def _load_plugins:
  """ read in plugins """
  pass

def _fetch_data:
  """ fetch data """
  pass

def _store_json:
  """ store JSON files """
  pass


if __name__ == "__main__":
    """Pull in the previous day's events by default"""

    to_date = date.today()
    from_date = to_date + timedelta(days=-1)

    query_vulndb(from_date, to_date)
