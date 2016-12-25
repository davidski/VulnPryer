#!/usr/bin/env python

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
# from builtins import *

from requests import request
from requests_oauthlib import OAuth1 as oauth
import simplejson as json
from datetime import date, timedelta
import logging
from configparser import ConfigParser
from builtins import str

logger = logging.getLogger('vulnpryer.vulndb')

config = ConfigParser()
config.read('/etc/vulnpryer.conf')

consumer_key = config.get('VulnDB', 'consumer_key')
consumer_secret = config.get('VulnDB', 'consumer_secret')
request_token_url = config.get('VulnDB', 'request_token_url')
temp_directory = config.get('VulnDB', 'working_dir')
json_directory = config.get('VulnDB', 'json_dir')
page_size = int(config.get('VulnDB', 'page_size'))


def _fetch_data(from_date, to_date, page_size=20, first_page=1):
    """Fetch a chunk of vulndb"""

    from_date = from_date.strftime("%Y-%m-%d")
    to_date = to_date.strftime("%Y-%m-%d")

    logger.info("Working on date range: {} - {}".format(from_date, to_date))

    auth = oauth(consumer_key, consumer_secret,
                 request_token_url)
    # client = oauth2.Client(consumer)

    # initialize the page counter either at the first page or whatever page
    # was requested
    page_counter = first_page

    finished = False
    reply = dict()
    reply['results'] = []

    while not finished:
        url = 'https://vulndb.cyberriskanalytics.com' + \
              '/api/v1/vulnerabilities/find_by_date?' + \
              'start_date=' + from_date + '&end_date=' + to_date + '&page=' + \
              str(page_counter) + '&size=' + str(page_size) + \
              '&date_type=updated_on' + \
              '&nested=true'
        logger.debug("Working on url: {} ".format(url))

        resp = request(url=url, auth=auth)
        if resp.status_int == 404:
            logger.warning("Could not find anything for the week " +
                           "begining: {}".format(from_date))
            return
        if resp.status_int != 200:
            raise Exception("Invalid response {}.".format(resp['status']))

        logger.debug("\tHTTP Response code: " + str(resp.status_int))

        """parse response and append to working set"""
        page_reply = json.loads(resp.body_string())
        logger.debug("Retrieving page {} of {}."
                     .format(page_counter,
                             -(-page_reply['total_entries'] // page_size)))

        if len(page_reply['results']) < page_size:
            finished = True
            reply['results'].extend(page_reply['results'])
            reply['total_entries'] = page_reply['total_entries']
        else:
            page_counter += 1
        reply['results'].extend(page_reply['results'])

    logger.info("Returning {} out of {} results".format(str(len(
        reply['results'])), str(reply['total_entries'])))
    return reply


def query_vulndb(from_date, to_date, day_interval=1):
    """Query RBS's VulnDB for a chunk of data"""

    from dateutil.parser import parse
    import io

    if not isinstance(from_date, date):
        from_date = parse(from_date)

    if not isinstance(to_date, date):
        to_date = parse(to_date)

    current_date = from_date

    while (current_date < to_date):
        window_start = current_date
        current_date = current_date + timedelta(days=day_interval)
        window_end = current_date

        reply = _fetch_data(window_start, window_end, page_size)

        with io.open(json_directory + 'data_' + window_start.strftime(
                "%Y-%m-%d") + '.json', 'w', encoding='utf-8') as f:
            f.write(json.dumps(reply, ensure_ascii=False))
            f.close


if __name__ == "__main__":
    """Pull in the previous day's events by default"""

    to_date = date.today()
    from_date = to_date + timedelta(days=-1)

    query_vulndb(from_date, to_date)
