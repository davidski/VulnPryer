from distutils.core import setup
from setuptools import setup

setup(
    name='VulnPryer',
    version='0.0.1',
    author='David F. Severski',
    author_email='davidski@deadheaven.com',
    packages=['vulnpryer'],
    long_description=open('README.rst').read(),
    url='http://vulnpryer.net',
    install_requires=[
        "argparse >= 1.2.1",
        "boto >= 2.32.1",
        "filechunkio >= 1.5",
        "lxml >= 3.3.5",
        "oauth2 >= 1.5.211",
        "pandas >= 0.13.1",
        "pymongo >= 2.7.2",
        "restkit >= 4.2.2",
        "simplejson >= 3.6.2",
    ],
)