from setuptools import setup
from setuptools.command.install import install
import warnings


# Robust datafile deployment process courtesy
# http://stackoverflow.com/questions/34193900/how-do-i-distribute-fonts-with-my-python-package
class MoveConf(install):
    def run(self):
        """
        Performs the usual install process and then copies the sample conf
        into the etc directory
        """
        # perform the standard install process
        install.run(self)
        # try to deploy our configuration sample
        try:
            import os
            import shutil
            import vulnpryer as vp

            # Find where to store the conf file
            target_dir = os.path.dirname('etc')

            # Copy the sample config
            sample_conf = os.path.join(os.path.dirname(vp.__file__), 'conf')
            for file_name in os.listdir(sample_conf):
                if file_name[-5:] == '.conf':
                    old_path = os.path.join(sample_conf, file_name)
                    new_path = os.path.join(target_dir, file_name)
                    shutil.copyfile(old_path, new_path)
                    print("Copying {} -> {}".format(old_path,  new_path))

        except Exception:
            warnings.warn("WARNING: Unspecified issue deploying " +
                          "sample configuration file.")


setup(
    name='VulnPryer',
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
    test_suite='nose.collector',
    tests_require=['nose'],
    author='David F. Severski',
    author_email='davidski@deadheaven.com',
    description='Prying context into your vulnerability information.',
    packages=['vulnpryer'],
    long_description=open('README.rst').read(),
    url='https://github.com/davidski/VulnPryer',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security'
    ],
    install_requires=[
        "configparser >= 2.5.0",
        "boto3 >= 1.4.0",
        "filechunkio >= 1.8.0",
        "future >= 0.16.0",
        "lxml >= 3.7.1",
        "pymongo[tls] >= 3.4.0",
        "python-crontab >= 2.1.1",
        "python-dateutil >= 2.6.0",
        "requests >= 2.12.0",
        "requests_oauthlib >= 0.7.0",
        "simplejson >= 3.10.0"
    ],
    scripts=['bin/vulnpryer'],
    include_package_data=True,
    keywords='security vulnerability vulndb redseal',
    data_files=[('', ['conf/vulnpryer.conf.sample'])],
    cmdclass={'install': MoveConf}
)
