from distutils.core import setup
setup(
  name = 'ahvl',
  packages = ['ahvl'],
  version = '0.3',
  license = 'MIT',                                  # Chose a license from here: https://help.github.com/articles/licensing-a-repository
  description = 'Base libraries for the Netson HashiCorp Vault Lookup Plugin for Ansible',
  author = 'RH Sonnenberg',
  author_email = 'r.sonnenberg@netson.nl',
  url = 'https://github.com/netson/ahvl',           # Provide either the link to your github or to your website
  download_url = 'https://github.com/netson/ahvl/archive/v0_3.tar.gz',    # I explain this later on
  keywords = ['ansible', 'hashicorp', 'vault', 'lookup'],   # Keywords that define your package best
  install_requires=['passlib'],
  classifiers=[
    'Development Status :: 3 - Alpha',              # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
    'Intended Audience :: Developers',              # Define that your audience are developers
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',       # Again, pick a license
    'Programming Language :: Python :: 3',          # Specify which pyhton versions that you want to support
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
  ],
)