from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="ahvl",
    version="1.0.6",
    author="RH Sonnenberg",
    author_email="r.sonnenberg@netson.nl",
    description="Base libraries for the Ansible HashiCorp Vault Lookup (AHVL) Plugin by Netson",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    url="https://github.com/netson/ahvl",
    download_url='https://github.com/netson/ahvl/archive/v1.0.6.tar.gz',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    keywords = "ansible hashicorp vault lookup",
    install_requires=['passlib','hvac','pretty-bad-protocol'],
)
