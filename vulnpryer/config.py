#!/usr/bin/env python

from configparser import ConfigParser

def read_config(conf_file='/etc/vulnpryer.conf'):
    """Read the config file and return a config object"""
    config = ConfigParser()
    config.read(conf_file)
    return config
