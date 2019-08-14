## ahvl

Base libraries for the Ansible HashiCorp Vault Lookup (AHVL) Plugin by Netson

### Install

```python
pip install ahvl
```

Package will most likely be installed in ```/usr/local/lib/pythonX.X/dist-packages/ahvl``` on ubuntu systems

### Update instructions

* create a working directory ```mkdir /opt/ahvl && cd /opt/ahvl```
* make sure twine is installed ```pip install twine```
* make sure your github SSH key is available
* login to github ```ssh -T git@github.com```
* clone repository ```git clone git://github.com/netson/ahvl```
* set remote origin ```git remote set-url origin git@github.com:netson/ahvl.git```
* make changes as needed
* remove any dist folder that may exist ```rm -rf ./dist```
* determine next PyPi package version number, look at ```https://github.com/netson/ahvl/releases```
* change the ```version``` and ```download_url``` in ```setup.py```
* commit changes to git ```git add . && git commit -m "commit message"```
* push to master ```git push origin master```
* create a new release on github with the same version number as in ```download_url```
* create PyPi source distribution ```python setup.py sdist```
* upload package to PyPi using twine ```twine upload dist/*```
* DONE! :-)
