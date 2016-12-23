from setuptools import setup
from pkg_resources import Requirement, resource_filename

setup(
    name='VulnPryer',
    test_suite='nose.collector',
    tests_require=['nose'],
    version='0.0.1',
    author='David F. Severski',
    author_email='davidski@deadheaven.com',
    description='Prying context into your vulnerability information.',
    packages=['vulnpryer'],
    long_description=open('README.rst').read(),
    url='https://github.com/davidski/vulnpryer',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security'
    ],
    install_requires=[
        "boto3 >= 1.4.0",
        "filechunkio >= 1.8.0",
        "lxml >= 3.7.0",
        "oauth2 >= 1.9.0",
        "pymongo >= 3.4.0",
        "simplejson >= 3.10.0",
        "restkit >= 4.2.0",
        "configparser",
        "future",
    ],
    scripts=['bin/vulnpryer'],
    include_package_data=True,
    keywords='security vulnerability vulndb redseal',
    data_files=[('/etc', ['conf/vulnpryer.conf.sample'])],
)

filename = resource_filename(Requirement.parse("VulnPryer"), "conf/vulnpryer.conf.sample")