import setuptools

with open("DESCRIPTION.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ahvl",
    version="1.0.1",
    author="RH Sonnenberg",
    author_email="r.sonnenberg@netson.nl",
    description="Base libraries for the Ansible HashiCorp Vault Lookup (AHVL) Plugin by Netson",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    url="https://github.com/netson/ahvl",
    download_url='https://github.com/netson/ahvl/archive/v1.0.1.tar.gz',
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
    ],
    keywords = "ansible hashicorp vault lookup",
    install_requires=['passlib','hvac','pretty-bad-protocol'],
)
