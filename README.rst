|Build Status| |PyPI Version|

=========
VulnPryer
=========

Vulnerability Pryer - Prying context into your vulnerability data.

Description
===========

VulnPryer is the code behind a `vulnerability reprioritization project
<http://blog.severski.net/2014/08/introducing-vulnpryer.html>`__.

With access to a vulnerability data feed (the VulnDB commercial project by default), VulnPryer downloads the feed on
an incremental (daily) basis, populates a MongoDB data store, extracts features on all known vulnerabilities, adjusts
the publicly published severities of vulnerabilities based upon factors of interest to the user's
organization, and generates a mapping of the organization-specific vulnerabilities for importing into your
vulnerability management platform of choice (VulnPryer defaults to the `RedSeal <https://www.redseal.net/>`__ platform
by default).

Installation
============

VulnPryer may be set up the manually or via several automated methods.

Manual Installation
-------------------

1. Setup an instance of MongoDB (authentication not currently supported)
2. ``pip install vulnpryer``
3. ``cp /etc/vulnpryer.conf{.sample,}``
4. ``vi /etc/vulnpryer.conf`` #modify with your settings and credentials.
5. Set up the daily schedule via ``vulnpryer schedule``

Automated Installation
----------------------

Choices:

1. Use your configuration manager of choice to ``pip install``, configure the conf file,
   and set up the crontab entry. A sample Chef cookbook is available at
   `chef-vulnpryer <https://github.com/davidski/chef-vulnpryer>`__ which has all the
   dependencies resolved.
2. Run the VulnPryer Docker image (NOT YET AVAILABLE)

Requirements
------------

Python 2.7, 3.5, or 3.6

Usage
=====

VulnPryer polls daily updates from VulnDB and generates an updated RedSeal Threat Reference Library file with
CVSS scores adjusted to a customized version for posting on an Amazon S3 bucket. This is accomplished via the
``vulndb`` module for working with the VulnDB API, the ``shiploader`` module for loading that data into MongoDB and
creating feature extracts, and the ``forklift`` module for taking the feature file and applying a custom
formula for creating vulnerability severities and generating TRL files.

The simplest installation is scheduling the provided ``vulnpryer`` command line utility to run on a daily
basis. If you want to replace individual modules (e.g. to use a different prioritization scheme, import a different
vulnerability data feed), you can run the individual components manually:

1. vulndb.py
2. shiploader.py
3. forklift.py

Troubleshooting Common Errors
=============================

VulnPryer depends on the ``lxml`` python package, which in turn has a dependency on ``libxslt2``.
Windows: Download and install one of the unofficial python ``lxslt`` packages available `here <http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml>`__.
Ubuntu: ``apt-get install libxml2-dev libxslt1-dev python3-dev``

Contributing
============

Please note this project is released with a `Contributor Code of Conduct <CONDUCT.md>`.

By participating in this project you agree to abide by its terms.

Authors and Collaborators
=========================

VulnPryer is the creation of:

- David F. Severski (code creation)
- Kymberlee Price `@kym_possible <https://twitter.com/kym_possible>`__
- Michael Roytman `@mroytman <https://twitter.com/mroytman>`__

Sponsorship
===========

RBS has generously supported continued development of the VulnPryer project, providing technical assistance with the
VulnDB interface.

Acknowledgements
================

VulnPryer would not exist without the inspiration and assistance of the following individuals and organizations:

- `@alexcpsec <https://twitter.com/alexcpsec>`__ and `@kylemaxwell <https://twitter.com/alexcpsec>`__ for
  the `combine <https://github.com/mlsecproject/combine>`__ project. VulnPryer has cribbed heavily from the combine
  design pattern, including a crude aping of naming metaphors. :grin:
- `Risk Based Security <https://vulndb.cyberriskanalytics.com/>`__ (RBS) for providing the VulnDB product and for the
  support in getting this project off the ground.
- `Kenna Security <https://www.kennasecurity.com>`__ for providing the inspiration on this project and their
  continued support of the community.
- `RedSeal <https://www.redseal.net>`__ for providing the analysis platform for network security posture
  review and analysis.

.. |Build Status| image:: https://secure.travis-ci.org/davidski/VulnPryer.png
   :target: http://travis-ci.org/davidski/VulnPryer
.. |PyPI Version| image:: https://img.shields.io/pypi/v/VulnPryer.svg
   :target:  https://pypi.python.org/pypi/pypi/VulnPryer
