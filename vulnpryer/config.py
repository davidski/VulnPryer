from pkg_resources import get_distribution, DistributionNotFound
from configparser import ConfigParser


try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    # package is not installed
    pass


def _read_config(conf_file='/etc/vulnpryer.conf'):
    """Read the config file and return a config object"""
    config = ConfigParser()
    config.read(conf_file)
    return config


numeric_level = getattr(logging, "INFO", None)
# if not isinstance(numeric_level, int):
#    raise ValueError('Invalid log level; %s' % args.loglevel)
logging.basicConfig(stream=sys.stdout,
                    level=numeric_level,
                    format='%(asctime)s %(name)s %(levelname)s %(message)s')