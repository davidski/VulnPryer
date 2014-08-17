VulnPryer
=========

Vulnerability Pryer - It prys more information into/out of your vulnerability data.

#Description
Vulnerability Pryer

#Usage
VulnPryer may be set up the hard (manual) way and the easy (automated) way.

## Manual Installation
1. Install Mongo running on the localhost
2. git clone https://github.com/davidski/VulnPryer vulnpryer
3  cd ./vulnpryer
4. pip install -r requirements
5. cp vulnpryer.conf{.sample,}
6. vi vulnpryer.conf #modify with your settings and credentials.
7. ./vulnpryer.py #run the subcomponents manually: 
  1. vulndb.py
  2. mongo_loader.py
  3. trl.py

### Automated Installation
1. Use the [chef-vulnpryer](https://github.com/davidski/chef-vulnpryer) cookbook to set up a full stack with all your dependencies resolved.

#Acknowledgements
Thanks to @alexcpsec and @kylemaxwell for the 
[combine](https://github.com/mlsecproject/combine) project. VulnPryer has cribbed heavily from 
that design pattern.

Thanks to Risk Based Security (RBS) for providing the VulnDB product and for the support in 
getting this project off the ground.

Thanks to Risk I/O for providing the inspiration on this project and their continued 
support of the community.