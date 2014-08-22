#!/usr/bin/env python

import ConfigParser
from lxml import objectify
import gzip
import urllib2
import base64
import os
from lxml import etree
import pandas as pd
import logging

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

trl_source_url = config.get('RedSeal', 'trl_url')
username = config.get('RedSeal', 'username')
password = config.get('RedSeal', 'password')
temp_directory = config.get('VulnDB', 'working_dir')
s3_bucket = config.get('S3', 'bucket_name')
s3_region = config.get('S3', 'region')
s3_key = config.get('S3', 'key')


class HeadRequest(urllib2.Request):
    def get_method(self):
        return "HEAD"


def _read_trl(trl_location):
    """Read and Import TRL"""

    parsed = objectify.parse(gzip.open(trl_location))
    root = parsed.getroot()

    return root


def get_trl(trl_path):
    """Getch the TRL from RedSeal"""

    req = urllib2.Request(trl_source_url)
    base64str = base64.encodestring('%s:%s' % (username,
                                    password)).replace('\n', '')
    req.add_header("Authorization", "Basic %s" % base64str)
    result = urllib2.urlopen(req)

    with open(trl_path, "wb") as local_file:
        local_file.write(result.read())
        local_file.close()


def _read_vulndb_extract():
    """read in the extracted VulnDB data"""
    vulndb = pd.read_csv(temp_directory + 'vulndb_export.csv')
    return vulndb


def _remap_trl(trl_data, vulndb):
    """Rectify CVSS Values"""

    CVSS_High = 10
    CVSS_Medium = 7
    CVSS_Low = 4

    for vulnerability in trl_data.vulnerabilities.vulnerability:
        if vulndb[vulndb['CVE_ID'] == vulnerability.get('cveID')].empty:
            vulnerability.set('CVSSTemporalScore',
                              vulnerability.get('CVSSBaseScore'))
        elif vulndb[vulndb['CVE_ID'] ==
                    vulnerability.get('cveID')].public_exploit.any >= 1:
            vulnerability.set('CVSSTemporalScore', str(CVSS_High))
        elif vulndb[vulndb['CVE_ID'] ==
                    vulnerability.get('cveID')].private_exploit.any >= 1:
            vulnerability.set('CVSSTemporalScore', str(CVSS_Medium))
        else:
            vulnerability.set('CVSSTemporalScore', str(CVSS_Low))
    return trl_data


def _write_trl(trl_data, modified_trl_path):
    """Write the modified trl out to disk"""
    # etree.cleanup_namespaces(trl)
    obj_xml = etree.tostring(trl_data, xml_declaration=True,
                             pretty_print=True, encoding='UTF-8')
    with gzip.open(modified_trl_path, "wb") as f:
        f.write(obj_xml)


def modify_trl(original_trl):
    """public full trl modification script"""
    vulndb = _read_vulndb_extract()
    trl_data = _read_trl(original_trl)
    modified_trl_data = _remap_trl(trl_data, vulndb)

    new_trl_path = os.path.dirname(original_trl) + '/modified_trl.gz'
    _write_trl(modified_trl_data, new_trl_path)
    return new_trl_path


def post_trl(file_path):
    """store the TRL to S3"""

    from filechunkio import FileChunkIO
    import math
    import os
    import boto.s3
    conn = boto.s3.connect_to_region(s3_region)

    bucket = conn.get_bucket(s3_bucket)

    logging.info('Uploading %s to Amazon S3 bucket %s' % (
        file_path, s3_bucket))

    import sys

    def percent_cb(complete, total):
        sys.stdout.write('.')
        sys.stdout.flush()

    source_size = os.stat(file_path).st_size
    chunk_size = 10000000
    chunk_count = int(math.ceil(source_size / chunk_size))
    mp = bucket.initiate_multipart_upload(s3_key, encrypt_key=True,
                                          policy='public-read')
    for i in range(chunk_count + 1):
        offset = chunk_size * i
        bytes = min(chunk_size, source_size - offset)
        with FileChunkIO(file_path, 'r', offset=offset, bytes=bytes) as fp:
            mp.upload_part_from_file(fp, part_num=i + 1)
    mp.complete_upload()

    # old single part upload not used due to bug in boto with continuation
    # headers
    # from boto.s3.key import Key
    # k = Key(bucket)
    # k.key = key_name
    # k.set_contents_from_filename(file_path, cb=percent_cb, num_cb=10,
    #   encrypt_key=True, policy='public-read')

    return

if __name__ == "__main__":
    modify_trl('/tmp/trl.gz')
