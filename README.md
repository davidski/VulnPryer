VulnPryer
=========

Vulnerability Pryer - It prys more information into/out of your vulnerability data.

#Description
Vulnerability Pryer

#Usage
There is the hard way and the easy way.

## The hard way
1. Git clone into your target directory
2. Install dependencies (DOCUMENTATION PENDING)
  a. Mongo
  b. Python 2.7 + several modules
3. Copy `vulnpryer.conf.sample` to `vulnpryer.conf` and modify with your settings and credentials.
4. Launch `vulnpryer.py`, or run the subcomponents manually:
  a. vulndb.py
  b. mongo_loader.py
  c. trl.py

### The easy way
1. Use the chef-vulnpryer cookbook to set up a full stack with all your dependencies resolved.

#Thanks
Thanks to @alexcpsec and @kylemaxwell for the 
{combine)[https://github.com/mlsecproject/combine] project. VulnPryer has cribbed heavily from 
that design pattern.

Thanks to Risk Based Security (RBS) for providing the VulnDB product and for the support in 
getting this project off the ground.

Thanks to Risk I/O for providing the inspiration on this project and their continued 
support of the community.