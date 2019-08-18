# ahvl

Base libraries for the Ansible HashiCorp Vault Lookup (AHVL) Plugin by Netson

## Install package

```bash
pip install ahvl
```

Package will most likely be installed in ```/usr/local/lib/pythonX.X/dist-packages/ahvl``` on ubuntu systems

## Upgrade package

```bash
pip install --upgrade ahvl
```

## Requirements

These lookup plugin depend on the following software packages:

| Name            | Min. version | Comments |
|-----------------|--------------|----------|
| Ansible         | 2.7          | Doesn't really need an introduction here |
| HashiCorp Vault | 1.1.3        | Only KV storage engine version 2 is supported |
| GnuPG           | 2.1.17       | To generate GPG Keys |
| Libgcrypt       | 1.8.1        | Required by GnuPG |
| OpenSSL         | 1.1.1        | To generate SSH Keys and SSH Hostkeys |
| putty-tools     | 0.7.2        | To convert SSH keys to various formats |
| Python          | 3.6          | May work with other versions, but is untested |

Additionally, the following python packages are required. These should be installed automatically or be part of the default python distribution.

| Python package |
|----------------|
| distutils      |
| time           |
| passlib        |
| shutil         |
| subprocess     |
| re             |
| os             |
| hvac           |
| random         |


## Storage structure

This plugin, by default, stores different secrets at different paths in Vault.

The default paths are as follows:

| Secret type | Default path                 | Comments |
|------------ |------------------------------|----------|
| password    | ```hosts/{hostname}/{find}```      | Regular passwords are stored per host, so having the same 'find' on different hosts will lead to different passwords |
| sshkey      | ```sshkeys/{find}```               | SSH keys are usually per user, and are not usually unique per host |
| sshhostkey  | ```hosts/{hostname}/sshhostkeys``` | Hostkeys are, obviously, different per host, so are stored under hosts |
| gpgkey      | ```gpgkeys/{find}```               | GPG keys are usually per user, and are not usually unique per host |
| salt        | depends on lookup plugin     | If a salt is generated it will always be stored in vault to ensure idempotence across runs. The path for the salt will be based on the path of the secret, will have the same 'in', but appended with the hashtype and the fixed string 'salt' at the end |

The option ```path``` does not need to be provided to the lookup plugin, instead it will be calculated. However, if you wish to have a different storage structure, you can simply change the base values as you see fit. You can use the variables ```{find}``` and ```{hostname}``` in your paths. Please be aware of any conflicting paths though. A specific path for salts cannot be set and will always follow the rules above.


## Configuration Options

To give you maximum flexibility in configuring the behaviour of these lookup plugins, there are several ways you can set the option values, one taking precedence over the other. The order in which they are processed is as follows. The lowest number will have the highest priority.


| Priority | Method                | Example                                                          | Comments                                   |
|----------|-----------------------|------------------------------------------------------------------|--------------------------------------------|
| 1        | Lookup arguments      | ```lookup('ahvl_password', find='mysql' in='myuser', out='mysql41')``` | |
| 2        | Environment variables | ```AHVL_CONNECTION_AHVL_TOKEN=http://localhost:8200``` | |
| 3        | Prefixed variables    | ```ahvl_connection_ahvl_url:'http://localhost:8200'``` | |
| 4        | Nested variables      | ```ahvl_connection:```<br>```  ahvl_url: 'http://localhost:8200'``` | |
| 5        | ansible.cfg           | ```[ahvl_connection]```<br>```  ahvl_token: 'yourtoken'``` | Only supported for AHVL Connection details |
| 6        | Defaults              | ```None``` | Hardcoded in the lookup plugin |


### ahvl Vault connection options

Every lookup will generate at least a single request to the HashiCorp Vault. In case a new secret has been generated, or a search path doesn't exist yet, more than one request will be made. The following connection details can be set:

| Option name                  | Required | Value type | Possible values                   | Default value         | Comment |
|------------------------------|:--------:|:----------:|-----------------------------------|-----------------------|---------|
| ahvl_url                     | yes      | string     | protocol://fqdn:port              | http://localhost:8200 | |
| ahvl_auth_method             | yes      | string     | token / userpass / ldap / approle | token                 | vault authentication method |
| ahvl_namespace               | no       | string     |                                   | None                  | vault secret namespace |
| ahvl_validate_certs          | no       | boolean    | True/False                        | True                  | validate vault certificates; set to False if not using an https connection; if you're using self-signed certificates provide the root certificate in ahvl_cacert instead |
| ahvl_mount_point             | no       | string     |                                   | secret                | vault secret mount point |
| ahvl_cacert                  | no       | path       | /fullpath/to/file.crt             | None                  | (self-signed) certificate to verify https connection |
| ahvl_username                | no       | string     |                                   | None                  | vault login username; required if auth_method is userpass/ldap |
| ahvl_password                | no       | string     |                                   | None                  | vault login password; required if auth_method is userpass/ldap; it is strongly recommended to only set the password using the environment variable AHVL_CONNECTION_AHVL_PASSWORD |
| ahvl_role_id                 | no       | string     |                                   | None                  | vault login role id; required if auth_method is approle |
| ahvl_secret_id               | no       | string     |                                   | None                  | vault login secret id; required if auth_method is approle |
| ahvl_token                   | no       | string     |                                   | None                  | vault token; required if auth_method is token; it is strongly recommended to only set the token using the environment variable AHVL_CONNECTION_AHVL_TOKEN! |


### ahvl General options

These options apply to all lookup plugins and can (or sometimes must) be set for each lookup. With the exception of the ahvl_tmppath, these options cannot be set globally.

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| hostname                     | yes      | fqdn       |                             | inventory_hostname         | The hostname can/will be used as part of the search path |
| ahvl_tmppath                 | no       | path       | /fullpath/to/tmpdir         | ansible generated tmp path | **BEWARE:** The tmppath **WILL BE DELETED AT THE END OF EACH LOOKUP**! To be safe, leave this setting empty; ansible will provide a random temporary folder which can be safely deleted. |
| find                         | yes      | string     |                             | None                       | The find parameter is used as part of the search path |
| in                           | yes      | string     | depends on lookup plugin    | None                       | At the given search path, determine which key to look for |
| out                          | yes      | string     | plaintext / hexsha256 / hexsha512 / sha256crypt / sha512crypt / phpass / mysql41 / postgresmd5 | hexsha512 | The format in which the secret will be returned. The hex*, mysql41 and postgresmd5 formats provide a hash, the sha* and phpass functions will give you a salted hash. Each hostname/secret combination will have a unique hash and the hash will also be stored in vault to make sure each subsequent playbook run will not generate a new salt. For each hash function the correct salt is determined automatically based on best practices |
| path                         | no       | string     | {find} / {hostname}           | depends on lookup plugin   | The actual search path used to find secret in vault. If not specified, it will be determined by the lookup plugin. When setting the path directly, you can use the variables {find} and {hostname} which will be replaced by the correct values prior to querying vault. |
| autogenerate                 | no       | boolean    | True/False                  | True                       | Whether or not to automatically generate new secrets when they could not be found in vault or when the latest version of the secret has been deleted |
| renew                        | no       | boolean    | True/False                  | False                      | Forces renewal of the secret, regardless of whether it already exists or not; will not change the behaviour of the autogenerate option. Be careful when using this, as it will be triggered for each and every lookup where this option is True, particularly in loops! |

### ahvl Lookup Password options
### ahvl Lookup SSH Key options
### ahvl Lookup SSH Hostkey options
### ahvl Lookup GPG Key options

### ahvl Generate Password options
### ahvl Generate SSH Key options
### ahvl Generate SSH Hostkey options
### ahvl Generate GPG Key options
### ahvl Generate Salt options


## Update ahvl package instructions

* create a working directory ```mkdir /opt/ahvl && cd /opt/ahvl```
* make sure twine is installed ```pip install twine```
* make sure your github SSH key is available
* login to github ```ssh -T git@github.com```
* clone repository ```git clone git://github.com/netson/ahvl```
* set remote origin ```git remote set-url origin git@github.com:netson/ahvl.git```
* make changes as needed
* remove any dist folder that may exist ```rm -rf ./dist && rm MANIFEST```
* determine next PyPi package version number, look at ```https://github.com/netson/ahvl/releases```
* change the ```version``` and ```download_url``` in ```setup.py```
* commit changes to git ```git add . && git commit -m "commit message"```
* push to master ```git push origin master```
* create a new release on github with the same version number as in ```download_url```
* create PyPi source distribution ```python setup.py sdist```
* test package upload using twine ```twine upload --repository-url https://test.pypi.org/legacy/ dist/*```
* verify test results on ```https://test.pypi.org/manage/projects/```
* upload package to PyPi using twine ```twine upload dist/*```
* enter your ```username``` and ```password```
* DONE! :-)
