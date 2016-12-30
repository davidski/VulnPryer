|Build Status| |PyPI Version| |Coverage Status|

=========
VulnPryer
=========

Vulnerability Pryer - Prying context into your vulnerability data.

Description
===========

VulnPryer is the code behind a `vulnerability re-prioritization project
<http://blog.severski.net/2014/08/introducing-vulnpryer.html>`__. With a goal of identifying the vulnerabilities
that are most crucial to address inside an enterprise, VulnPryer adjusts the priorities (CVSS scores) on publicly
identified vulnerabilities.

With access to a vulnerability data feed (currently `Risk Based Security's
VulnDB <https://www.riskbasedsecurity.com/vulndb/>`__ subscription project),
VulnPryer downloads the feed of new and updated vulnerabilities on an incremental (daily) basis, populates a
MongoDB data store, extracts features on all known vulnerabilities, adjusts the default CVSS scores of
vulnerabilities based upon factors of interest to the user's organization, and generates a mapping of the
organization-specific vulnerabilities for importing into your vulnerability management platform of choice
(currently the `RedSeal <https://www.redseal.net/>`__ platform).

Installation
============

VulnPryer may either be set up manually or via one of several example automated methods. VulnPryer requires a static
datafile directory to use for storing vulnerability update files. While a MongoDB data store is also used, this is
rebuilt each run and is effectively ephemeral between runs. The datafile directory, in comparison, needs to be
persistent.

Manual Installation
-------------------

To set up VulnPryer on a persistent host:

1. Set up an instance of MongoDB
2. ``pip install vulnpryer``
3. ``cp /etc/vulnpryer.conf{.sample,}``
4. Modify ``/etc/vulnpryer.conf`` with settings for your environment. Key settings include:

  a. Mongo:URI = URI to your instance. Defaults to unauthenticated SSL with localhost
  b. VulnDB API key
  c. RedSeal support username and password
  d. Datafile store (MUST BE PERSISTENT)
  e. S3 bucket location (will use EC2 instance profile if no IAM keys provided)

5. Set up an automated daily import job by running ``vulnpryer schedule``

Automated Installation
----------------------

Choices:

1. Use your configuration manager of choice to ``pip install``, configure the conf file,
   and set up the crontab entry. A sample Chef cookbook is available at
   `chef-vulnpryer <https://github.com/davidski/chef-vulnpryer>`__ which will set up the python
   environment and can optionally be used to schedule VulnPryer runs along with managing a persistent data store via
   AWS EBS volumes.
2. Run the VulnPryer Docker image (NOT YET AVAILABLE)

Requirements
------------

Platforms: Unix host (Windows may work, on an experimental basis)
Data store: MongoDB (tested with v3.4.1, v2 should also work)
Interpreter: Python 2.7, 3.5, or 3.6

Usage
=====

VulnPryer polls daily updates from VulnDB, generates an updated RedSeal Threat Reference Library (TRL) file with
custom CVSS scores, and posts the updated TRL to an Amazon S3 bucket. The simplest installation is scheduling the
provided ``vulnpryer`` command line utility to run on a daily basis. If you want to replace individual modules
(e.g. to use a different prioritization scheme, import a different vulnerability data feed), you can run the individual
modules manually:

1. vulndb.py - works with the VulnDB API
2. shiploader.py - loads data into MongoDB and creates feature extracts
3. forklift.py - applies the feature extract with a custom formula, updates vulnerability severities, and generates
   the TRL files

Troubleshooting Common Installation Errors
==========================================

VulnPryer depends on the ``lxml`` python package, which in turn has a dependency on ``libxslt2``.

- Ubuntu: ``apt-get install libxml2-dev libxslt1-dev python3-dev``
- Windows: Download and install one of the unofficial python ``lxslt`` packages available
  `here <http://www.lfd.uci.edu/~gohlke/pythonlibs/#lxml>`__.

Contributing
============

Please note this project is released with a `Contributor Code of Conduct <CONDUCT.md>`__.

By participating in this project you agree to abide by its terms.

Authors and Collaborators
=========================

The core members of the VulnPryer project are:

- Kymberlee Price `@kym_possible <https://twitter.com/kym_possible>`__
- Michael Roytman `@mroytman <https://twitter.com/mroytman>`__
- David F. Severski - code creation - `@dseverski <https://twitter.com/dseverski>`__

Sponsorship
===========

`Risk Based Security <https://www.riskbasedsecurity.com/>`__ has generously supported continued development of the
VulnPryer project, providing technical assistance with the VulnDB interface.

Acknowledgements
================

VulnPryer would not exist without the inspiration and assistance of the following individuals and organizations:

- `@alexcpsec <https://twitter.com/alexcpsec>`__ and `@kylemaxwell <https://twitter.com/alexcpsec>`__ for
  the `combine <https://github.com/mlsecproject/combine>`__ project. VulnPryer has cribbed heavily from the combine
  design pattern, including a crude aping of naming metaphors.
- `Risk Based Security <https://vulndb.cyberriskanalytics.com/>`__ (RBS) for providing the VulnDB product and for
  support in getting this project off the ground.
- `Kenna Security <https://www.kennasecurity.com>`__ for providing the inspiration on the project and their
  continued support of the security community.
- `RedSeal <https://www.redseal.net>`__ for providing an excellent platform for network security posture review and
  analysis.

.. |Build Status| image:: https://secure.travis-ci.org/davidski/VulnPryer.png
   :target: http://travis-ci.org/davidski/VulnPryer
.. |PyPI Version| image:: https://img.shields.io/pypi/v/VulnPryer.svg
   :target:  https://pypi.python.org/pypi/pypi/VulnPryer
.. |Coverage Status| image:: https://coveralls.io/repos/github/davidski/vulnpryr/badge.svg
   :target: https://coveralls.io/github/davidski/vulnpryr
