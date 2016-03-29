#!/usr/bin/env python

import simplejson as json
#!/usr/bin/env python

import simplejson as json
from datetime import date, timedelta
import logging
import ConfigParser

logger = logging.getLogger('vulnpryer.feed')

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

def _load_plugins:
  """read in plugins"""
  pass

def _init_plugin:
  """allow plugin to perform any setup functionality"""
  pass

def fetch_feed:
  """ fetch data """
  pass

def _shutdown_plugin:
  """allow plugin to shutdown cleanly"""
  pass

def store_json:
  """store JSON files"""
  pass


if __name__ == "__main__":
    """Pull in the previous day's events by default"""

    to_date = date.today()
    from_date = to_date + timedelta(days=-1)

    fetch_feed(from_date, to_date)
from datetime import date, timedelta
import logging
import ConfigParser
from yapsy.PluginManager import PluginManager

logger = logging.getLogger('vulnpryer.feed')

config = ConfigParser.ConfigParser()
config.read('vulnpryer.conf')

manager = PluginManager()
manager.setPluginPlaces(["plugins"])

manager.setCategoriesFilter({
    "Store": IStorePlugin,
    "Feed": IFeedPlugin
    })
#manager.collectPlugins()
manager.collectPlugins()

for plugin in manager.getPluginsOfCategory("Feed"):
    plugin.plugin_object.print_name()

def load_plugins:
    """read in plugins"""
  pass

def init_plugin:
    """allow plugin to perform any setup functionality"""
  plugin.connect()
  pass

def fetch_feed(from_date, to_date):
    """ fetch data """
  pass

def shutdown_plugin:
    """allow plugin to shutdown cleanly"""
  pass

def store_json:
    """store JSON files"""
  pass


if __name__ == "__main__":
    """Pull in the previous day's events by default"""

    to_date = date.today()
    from_date = to_date + timedelta(days=-1)

    fetch_feed(from_date, to_date)
