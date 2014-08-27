[![Build Status](https://secure.travis-ci.org/davidski/VulnPryer.png)](http://travis-ci.org/davidski/VulnPryer)

VulnPryer
=========

Vulnerability Pryer - Pries more context into your vulnerability data.

#Description
VulnPryer is the code behind a [vulnerability reprioritization project](http://blog.severski.net/2014/08/introducing-vulnpryer.html). 
Using a vulnerability data feed (VulnPryer uses the VulnDB commercial project by default), VulnPryer will 
download that feed on an incremental basis, load the feed into MongoDB for storage, extract a 
mapping of features, and provide a remapping of vulnerabilities to custom severities for importing 
into your analysis product of choice (VulnPryer targets the [RedSeal](https://www.redsealnetworks.com/) platform by default).

#Installation
VulnPryer may be set up the hard (manual) way and the easy (automated) way.

## Manual Installation
1. Setup an instance of MongoDB (authentication not currently supported)
2. git clone https://github.com/davidski/VulnPryer vulnpryer
3  cd ./vulnpryer
4. pip install -r requirements
5. cp vulnpryer.conf{.sample,}
6. vi vulnpryer.conf #modify with your settings and credentials.

## Automated Installation
1. Use the [chef-vulnpryer](https://github.com/davidski/chef-vulnpryer) cookbook to set up a full stack with all your dependencies resolved.
2. Profit!

#Usage
VulnPryer targets running daily extracts out of VulnDB and generating updated RedSeal Threat 
Reference Library files with modified CVSS ratings on an Amazon S3 bucket. This is accomplished 
via the `vulndb` module for working with the VulnDB API, the `shiploader` module for loading that 
data into MongoDB and creating feature extracts, and the `forklift` module for taking the feature file and 
applying a custom formula for creating vulnerability severities and generating TRL files.

The simplest means is to run the `vulnpryer.py` wrapper script. If you want to replace indlvidual 
modules (e.g. to use a different prioritization scheme, import a different vulnerability data feed), 
you can run the individual compoents manually:

  1. vulndb.py
  2. shiploader.py
  3. forklift.py

#Acknowledgements
VulnPryer would not exist without the inspiration and assistance of the following individuals 
and organizations:
- [@alexcpsec](https://twitter.com/alexcpsec) and 
[@kylemaxwell](https://twitter.com/alexcpsec) for the 
[combine](https://github.com/mlsecproject/combine) project. VulnPryer has cribbed heavily from 
that design pattern, including a crude aping of naming metaphors. :grin:
- (Risk Based Security)[https://vulndb.cyberriskanalytics.com/] (RBS) 
for providing the VulnDB product and for the support in getting this project 
off the ground.
- (Risk I/O)[https://www.risk.io/] for providing the inspiration 
on this project and their continued support of the community.
- (RedSeal){https://www.redsealnetworks.com] for providing the analysis platform for network 
security posture review and analysis.