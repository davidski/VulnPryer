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
import tempfile
import re

logger = logging.getLogger('vulnpryer.score')

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

def _read_vulndb_extract():
    """read in the extracted VulnDB data"""
    vulndb = pd.read_csv(temp_directory + 'vulndb_export.csv')
    return vulndb


def _rescore(vulnerability):
    """Rectify CVSS Values"""

    avg_cvss_score = 6.2
    msp_factor = 2.5
    edb_factor = 1.5
    private_exploit_factor = .5
    network_vector_factor = 2
    impact_factor = 3

    for vulnerability in trl_data.vulnerabilities.vulnerability:

        logger.debug('Adjusting priority of {}'.format(
            vulnerability.get('cveID')))

        # start off with the NVD definition
        modified_score = float(vulnerability.get('CVSSTemporalScore'))
        # add deviation from mean
        modified_score = modified_score + (modified_score -
                                           avg_cvss_score) / avg_cvss_score
        # adjust up if metasploit module exists
        if vulndb[vulndb['CVE_ID'] ==
                  vulnerability.get('cveID')].msp.any >= 1:
                    modified_score = modified_score + msp_factor
        # adjust up if exploit DB entry exists
        if vulndb[vulndb['CVE_ID'] ==
                  vulnerability.get('cveID')].edb.any >= 1:
                    modified_score = modified_score + edb_factor
        # adjust up if a private exploit is known
        if vulndb[vulndb['CVE_ID'] ==
                  vulnerability.get('cveID')].private_exploit.any >= 1:
                    modified_score = modified_score + private_exploit_factor
        else:
            modified_score = modified_score - private_exploit_factor
        # adjust down for impacts that aren't relevant to our loss scenario
        if (vulndb[vulndb['CVE_ID'] ==
            vulnerability.get('cveID')].impact_integrity.any < 1 and
            vulndb[vulndb['CVE_ID'] ==
                   vulnerability.get('cveID')].impact_confidentiality.any < 1):
                modified_score = modified_score - impact_factor
        # adjust down for attack vectors that aren't in our loss scenario
        if vulndb[vulndb['CVE_ID'] ==
                  vulnerability.get('cveID')].network_vector.any < 1:
                    modified_score = modified_score - network_vector_factor
        # confirm that our modified score is within max/min limits
        if modified_score > 10:
            modified_score = 10
        if modified_score < 0:
            modified_score = 0
        # set the modified score
        vulnerability.set('CVSSTemporalScore', str(modified_score))
    logger.debug('Completed adjustments to TRL.')
    return trl_data


if __name__ == "__main__":
    modify_trl('/tmp/trl.gz')
