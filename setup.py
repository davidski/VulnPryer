from setuptools import setup

setup(
    name='VulnPryer',
    test_suite='nose.collector',
    tests_require=['nose'],
    version='0.0.1',
    author='David F. Severski',
    author_email='davidski@deadheaven.com',
    packages=['vulnpryer'],
    long_description=open('README.rst').read(),
    url='https://github.com/davidski/vulnpryer',
    install_requires=[
        "boto3 >= 1.4.0",
        "filechunkio >= 1.8.0",
        "lxml >= 3.7.0",
        "oauth2 >= 1.9.0",
        "pymongo >= 3.4.0",
        "simplejson >= 3.10.0",
    ],
)
