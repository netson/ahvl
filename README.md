# ahvl

Base libraries for the Ansible HashiCorp Vault Lookup (AHVL) Plugin by Netson



## Contents

* [Introduction](#introduction)
  * [Secrets](#secrets)
  * [Output filters](#output-filters)
* [Requirements](#requirements)
* [Installation](#installation)
* [Storage structure](#storage-structure)
* [Examples](#examples)
  * [Passwords](#passwords)
* [Configuration options](#configuration-options)
  * [ahvl Lookup Password options](#ahvl-lookup-password-options)
  * [ahvl Lookup SSH Key options](#ahvl-lookup-ssh-key-options)
  * [ahvl Lookup SSH Hostkey options](#ahvl-lookup-ssh-hostkey-options)
  * [ahvl Lookup GPG Key options](#ahvl-lookup-gpg-key-options)
  * [ahvl Lookup Credential options](#ahvl-lookup-credential-options)
  * [ahvl Generate Password options](#ahvl-generate-password-options)
  * [ahvl Generate SSH Key options](#ahvl-generate-ssh-key-options)
  * [ahvl Generate SSH Hostkey options](#ahvl-generate-ssh-hostkey-options)
  * [ahvl Generate GPG Key options](#ahvl-generate-gpg-key-options)
  * [ahvl Generate Salt options](#ahvl-generate-salt-options)



## Introduction

#### Short version

A set of lookup plugins which retrieves secrets from HashiCorp Vault, and generates them automatically if they don't exist. It support generating passwords, SSH keys, SSH hostkeys and GPG keys. Keys are generated and converted to various formats to support a wide range of applications. All aspects of the various keys are stored in vault and accessible. Each secret can be passed through an output filter or hash function so no further processing is necessary. Hash functions which require a salt will store the salt in Vault as well to maintain idempotence.

#### TL;DR

Managing secrets properly is tough. Even though there are great tools available which help you manage, rotate and audit your secrets properly, it still requires a significant effort. These ansible lookup plugins aim to make that process easier. When managing many servers with Ansible, the number of secrets you need to manage just keeps growing and even though Ansible provides its own Ansible Vault as a means to store these secrets in an encrypted form, I still found the process to be quite cumbersome and I wanted to keep all my secrets out of version control entirely, encrypted or not.

My first attempt at using a different secrets store, other than Ansible Vault, was built on KeePass which I have used successfully and happily for over 10 years now. After spending a good amount of time developing a lookup plugin for keepass I ran into a major issue: performance! For each lookup, the KeePass database had to be unlocked, decrypted, searched, encrypted and closed again. For a few lookups, this was not an issue, but since we're talking seconds per lookup, this didn't seem like a scalable solution. Enter HashiCorp Vault. HashiCorp Vault was built specifically for the purpose of managing secrets and provided important features straight out of the box: auditing, fine-grained access control, versioning, etc.

The next major issue I have is with generating secrets; when creating user accounts, when setting up databases, when generating SSH keys and potentially having to convert them because your end user uses Putty on a windows system, when generating GPG keys to protect automated backups etc. etc. Generating the secrets is one thing, but then you need to store these secrets in vault in order to be able to retrieve them in your playbooks. Again, quite a time consuming process, not to mention the risk of generating insecure secrets due to missing parameters, insecure system defaults, poorly configured tools, or simply a lack of sleep!

Then another issue I had with the manual secret managing process, is that often you need secrets in a particular format for a specific purpose. I already mentioned the SSH key that needs to be converted to the Putty format, but when creating a user account, you may need the password to be hashed as a sha256crypt hash or a particular application hash such as the MySQL41 hash.

Previously I had a bunch of bash scripts to help me generate and convert all these secrets, but storing them safely was always cumbersome. These lookup plugins attempt to solve all these issues at once! Keep all secrets out of version control, store them securly in HashiCorp Vault, and when you request a secret which does not exist (yet), it will simply generate it for you on the fly and store it in Vault! Last but not least, you can request the specific output that you need and the plugin will return the converted secret!

#### Secrets

Various types of secrets are supported, seperated into seperate lookup plugins. For all lookup plugins sane and secure defaults have been set, but you can manipulate almost all aspects of the secret generating process using variables to match your needs.

| Type | Description |
|------|-------------|
| Passwords | This lookup plugin will return straight forward passwords. It uses the python library Passlib to generate secure secrets. |
| SSH keys | This lookup plugin allows you to fetch every aspect of an SSH key: private key in various formats (OpenSSH, Putty, SSHCOM, PKCS8), public key in various formats (OpenSSH, PEM, PKCS8, RFC4716), but also the MD5 and SHA256 fingerprints, the key art and bubblebabble and of course the password! |
| SSH hostkeys | This lookup plugin will generate a set of SSH hostkeys in 2 formats (RSA and Ed25519), the matching DNS entries, fingerprints and bubblebabble. Never again do you have an excuse to not have you knownhosts file out of date or to support the older, insecure hostkey formats. |
| GPG keys | This lookup plugin allows you to generate 2 sets of keys on the fly. The 'regular' setting will generate a single master key (cert only) and 3 subkeys, each with a single responsibility (sign, encr or auth). All aspects of the generated key can be retrieved, from the KeyID, fingerprint and keygrip to the expiration date, private key (armored) and of course the password. The 'backup' setting will generate 2 master keys, each with a single subkey. One will be used for signing only, the other for encryption only. The encryption key will be signed by the signing key. Again, all aspects of each key will be stored in vault and can be retrieved. |
| Credentials | Credentials are similar to passwords, however, they differ on 1 main aspect: credentials are never automatically generated. I use these to store my AWS, GCP, API keys and other sorts of external credentials which are needed by various playbooks. |

#### Output filters

Each of the above secrets can be run through an output filter before being returned to your playbook. If you select a hashing algorithm which requires a salt, the lookup plugin will automatically generate a unique salt for you and store this salt in Vault as well, to make sure that each subsequent playbook run maintains idempotence. For each combination of secret, hostname and hashing algorithm, a unique salt is generated and stored next to the requested secret so they can be easily found and salt reuse is limited as much as possible accross hosts and services. The following output filters are supported:

| Filter/Out | Description |
|--------|-------------|
| plaintext | Returns the plaintext version |
| hexsha256 | Returns the sha256 hashed version |
| hexsha512 | Returns the sha512 hashed version |
| sha256crypt | Return the Crypt hashed and salted SHA-256 version |
| sha512crypt | Returns the Crypt hashed and salted SHA-512 version |
| pbkdf2sha256 | Return the PBKDF2 hashed and salted SHA-256 version |
| pbkdf2sha512 | Return the PBKDF2 hashed and salted SHA-512 version |
| grubpbkdf2sha512 | Return the GRUB specific PBKDF2 hashed and salted SHA-512 version |
| phpass | Returns the PHPass hashed and salted version |
| mysql41 | Returns the MySQL41 hashed version |
| postgresmd5 | Returns the PostgreSQL hashed version (uses the 'in' parameter as username |
| argon2 | Returns the Argon2 hashed and salted version |



## Requirements

These lookup plugins depend on the following software packages:

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
| packaging      |
| argon2-cffi    |



## Installation

#### Install package

```bash
pip install ahvl
```

Package will most likely be installed in ```/usr/local/lib/pythonX.X/dist-packages/ahvl``` on ubuntu systems

#### Upgrade package

```bash
pip install --upgrade ahvl
```



## Storage structure

These lookup plugins, by default, store different secrets at different paths in Vault.

The default paths are as follows:

| Secret type | Default path                 | Comments |
|------------ |------------------------------|----------|
| `password`    | `hosts/{hostname}/{find}`      | Regular passwords are stored per host, so having the same 'find' on different hosts will lead to different passwords |
| `sshkey`      | `sshkeys/{find}`               | SSH keys are usually per user, and are not usually unique per host |
| `sshhostkey`  | `hosts/{hostname}/sshhostkeys` | Hostkeys are, obviously, different per host, so are stored under hosts |
| `gpgkey`      | `gpgkeys/{find}`               | GPG keys are usually per user, and are not usually unique per host |
| `credential`  | `credentials/{find}`           | Credentials (AWS, API keys, etc) are stored seperately |
| `salt`        | Always at the same path as the secret | If a salt is generated it will always be stored in vault to ensure idempotence across runs. The path for the salt will be based on the path of the secret, will have the same 'in', but appended with the hostname, hashtype and the fixed string 'salt' at the end |

The option ```path``` does not need to be provided to the lookup plugin, instead it will be calculated. However, if you wish to have a different storage structure, you can simply change the base values as you see fit. You can use the variables ```{find}``` and ```{hostname}``` in your paths. Please be aware of any conflicting paths though. A specific path for salts cannot be set and will always follow the rules above.

Using the default settings, you will end up with a structure that looks similar to the one below. The lowest levels will contain the key/value combinations.

```
+-secret/
  +-credentials/
    +-aws/
    +-gcp/
  +-hosts/
    +-srv1.example.com/
      +-sshhostkeys/
        +-ed25519/
        +-rsa/
      +-mariadb/
  +-sshkeys/
    +-myuser/
  +-gpgkeys/
    +-someusr/
```



## Examples

#### HashiCorp Vault connection

```ini
# ansible.cfg

...
# connection details for HashiVault lookup plugin
[ahvl_connection]
ahvl_url = https://192.168.1.100:8200
ahvl_auth_method = token
ahvl_validate_certs = True
ahvl_cacert = /usr/local/share/ca-certificates/Netson_CA.crt

```
```ini
# /etc/environment
...
AHVL_CONNECTION_AHVL_TOKEN=<myvaulttoken>
PASSLIB_MAX_PASSWORD_SIZE=16384 # to prevent error when using the hash function on (very) large passwords or keys
```

#### Passwords

```yaml
---
# playbook to demonstrate ahvl_password

- hosts: localhost
  gather_facts: no

  vars:
    output_filters:
      - plaintext
      - hexsha256
      - hexsha512
      - sha256crypt
      - sha512crypt
      - phpass
      - mysql41
      - postgresmd5
      - pbkdf2sha256
      - pbkdf2sha512
      - argon2
      - grubpbkdf2sha512

  tasks:

  # the path in vault which will be searched is [hosts/localhost/mariadb] on the default mountpoint
  - name: 'ahvl_password : get password for MariaDB account with username myuser and show all outputs'
    debug:
      msg: "{{ lookup('ahvl_password', find='mariadb', in='myuser', out=item) }}"
    loop: "{{ output_filters }}"

  - name: 'ahvl_password : get password (length=8, type=phrase - will result in 8 words) for MariaDB account with username anotheruser and output the mysql41 hash'
    debug:
      msg: "{{ lookup('ahvl_password', find='mariadb', in='anotheruser', out='mysql41', pwd_length=8, pwd_type='phrase') }}"
```

#### SSH keys

```yaml
---
# playbook to demonstrate ahvl_sshkey

- hosts: localhost
  gather_facts: no

  vars:
    ahvl_generate_sshkey:
      sshkey_pkcs8_enabled: yes # requires openssl 6.5+
      sshkey_putty_enabled: yes # requires puttygen 0.72+

    # PCKS8 and SSHCOM do not support Ed25519 keys
    sshkey_ed25519_in:
      - password
      - private
      - private_keybits
      - private_keytype
      - private_openssh
      - private_putty
      - public
      - public_rfc4716
      - fingerprint_sha256
      - fingerprint_sha256_clean
      - fingerprint_sha256_art
      - fingerprint_md5
      - fingerprint_md5_clean
      - fingerprint_md5_art
      - fingerprint_bubblebabble
      - fingerprint_bubblebabble_clean
      - fingerprint_putty

    sshkey_rsa_in:
      - password
      - private
      - private_keybits
      - private_keytype
      - private_pkcs8
      - private_openssh
      - private_putty
      - private_sshcom
      - public
      - public_pem
      - public_pkcs8
      - public_rfc4716
      - fingerprint_sha256
      - fingerprint_sha256_clean
      - fingerprint_sha256_art
      - fingerprint_md5
      - fingerprint_md5_clean
      - fingerprint_md5_art
      - fingerprint_bubblebabble
      - fingerprint_bubblebabble_clean
      - fingerprint_putty

  tasks:

  - name: 'ahvl_sshkey : fetch/generate SSH key of type Ed25519 and output all information pieces'
    debug:
      msg: "{{ lookup('ahvl_sshkey', find='myusername', in=item, out='plaintext') }}"
    loop: "{{ sshkey_ed25519_in }}"

  - name: 'ahvl_sshkey : rsa'
    debug:
      msg: "{{ lookup('ahvl_sshkey', find='anotherusername', sshkey_type='rsa', in=item, out='plaintext') }}"
    loop: "{{ sshkey_rsa_in }}"
```

#### SSH hostkeys

```yaml
---
# playbook to demonstrate ahvl_sshhostkey

- hosts: localhost
  gather_facts: no

  vars:
    sshhostkey_ins:
      - private
      - public
      - fingerprint_sha256
      - fingerprint_sha256_clean
      - fingerprint_sha256_art
      - fingerprint_md5
      - fingerprint_md5_clean
      - fingerprint_md5_art
      - fingerprint_bubblebabble
      - fingerprint_bubblebabble_clean
      - dns_sha1
      - dns_sha1_clean
      - dns_sha256
      - dns_sha256_clean

  tasks:

  # search path used for vault will be [hosts/localhost/sshhostkeys/rsa]
  - name: 'ahvl_sshhostkey : lookup RSA hostkey and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_sshhostkey', find='rsa', in=item, out='plaintext') }}"
    loop: "{{ sshhostkey_ins }}"

  # search path used for vault will be [hosts/localhost/sshhostkeys/ed25519]
  - name: 'ahvl_sshhostkey : lookup Ed25519 hostkey and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_sshhostkey', find='ed25519', in=item, out='plaintext') }}"
    loop: "{{ sshhostkey_ins }}"

  # search path used for vault will be [hosts/myhost2.local/sshhostkeys/rsa]
  - name: 'ahvl_sshhostkey : lookup RSA for another host and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_sshhostkey', find='rsa', in=item, sshhostkey_type='rsa', out='plaintext', hostname='myhost2.local') }}"
    loop: "{{ sshhostkey_ins }}"
```

#### GPG keys

```yaml
---
# playbook to demonstrate ahvl_gpgkey

- hosts: localhost
  gather_facts: no

  vars:
    gpgkey_regular_ins:
      - master_cert_pub_key_armored
      - master_cert_sec_key_armored
      - master_cert_sec_keytype
      - master_cert_sec_keyuid
      - master_cert_sec_password
      - master_cert_sec_fingerprint
      - master_cert_sec_keycurve
      - master_cert_sec_keygrip
      - master_cert_sec_keybits
      - master_cert_sec_creationdate
      - master_cert_sec_keyid
      - master_cert_sec_expirationdate
      - subkey_sign_sec_key_armored
      - subkey_sign_sec_fingerprint
      - subkey_sign_sec_keycurve
      - subkey_sign_sec_keygrip
      - subkey_sign_sec_keybits
      - subkey_sign_sec_creationdate
      - subkey_sign_sec_keyid
      - subkey_sign_sec_expirationdate
      - subkey_encr_sec_key_armored
      - subkey_encr_sec_fingerprint
      - subkey_encr_sec_keycurve
      - subkey_encr_sec_keygrip
      - subkey_encr_sec_keybits
      - subkey_encr_sec_creationdate
      - subkey_encr_sec_keyid
      - subkey_encr_sec_expirationdate
      - subkey_auth_sec_key_armored
      - subkey_auth_sec_fingerprint
      - subkey_auth_sec_keycurve
      - subkey_auth_sec_keygrip
      - subkey_auth_sec_keybits
      - subkey_auth_sec_creationdate
      - subkey_auth_sec_keyid
      - subkey_auth_sec_expirationdate
    gpgkey_backup_ins:
      - sign_master_cert_pub_key_armored
      - sign_master_cert_sec_key_armored
      - sign_master_cert_sec_keytype
      - sign_master_cert_sec_keyuid
      - sign_master_cert_sec_password
      - sign_master_cert_sec_fingerprint
      - sign_master_cert_sec_keycurve
      - sign_master_cert_sec_keygrip
      - sign_master_cert_sec_keybits
      - sign_master_cert_sec_creationdate
      - sign_master_cert_sec_keyid
      - sign_master_cert_sec_expirationdate
      - sign_subkey_sign_sec_key_armored
      - sign_subkey_sign_sec_fingerprint
      - sign_subkey_sign_sec_keycurve
      - sign_subkey_sign_sec_keygrip
      - sign_subkey_sign_sec_keybits
      - sign_subkey_sign_sec_creationdate
      - sign_subkey_sign_sec_keyid
      - sign_subkey_sign_sec_expirationdate
      - encr_master_cert_pub_key_armored
      - encr_master_cert_sec_key_armored
      - encr_master_cert_sec_keytype
      - encr_master_cert_sec_keyuid
      - encr_master_cert_sec_password
      - encr_master_cert_sec_fingerprint
      - encr_master_cert_sec_keycurve
      - encr_master_cert_sec_keygrip
      - encr_master_cert_sec_keybits
      - encr_master_cert_sec_creationdate
      - encr_master_cert_sec_keyid
      - encr_master_cert_sec_expirationdate
      - encr_subkey_encr_sec_key_armored
      - encr_subkey_encr_sec_fingerprint
      - encr_subkey_encr_sec_keycurve
      - encr_subkey_encr_sec_keygrip
      - encr_subkey_encr_sec_keybits
      - encr_subkey_encr_sec_creationdate
      - encr_subkey_encr_sec_keyid
      - encr_subkey_encr_sec_expirationdate

  tasks:

  # search path used for vault will be [gpgkeys/name_ed25519_localhost_myemail]
  - name: 'ahvl_gpgkey : fetch/generate regular ed25519 key and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_gpgkey', gpgkey_fullname='name_ed25519', gpgkey_email='myemail', in=item, out='plaintext') }}"
    loop: "{{ gpgkey_regular_ins }}"

  # search path used for vault will be [gpgkeys/name_rsa_localhost_myemail]
  - name: 'ahvl_gpgkey : fetch generate regular RSA key and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_gpgkey', gpgkey_type='rsa', gpgkey_fullname='name_rsa', gpgkey_email='myemail', in=item, out='plaintext') }}"
    loop: "{{ gpgkey_regular_ins }}"

  # search path used for vault will be [gpgkeys/bckp_ed25519_localhost_myemail]
  - name: 'ahvl_gpgkey : fetch/generate backup ed25519 key and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_gpgkey', gpgkey_keyset='backup', gpgkey_fullname='bckp_ed25519', gpgkey_email='myemail', gpgkey_comment=inventory_hostname, in=item, out='plaintext') }}"
    loop: "{{ gpgkey_backup_ins }}"

  # search path used for vault will be [gpgkeys/bckp_rsa_localhost_myemail]
  - name: 'ahvl_gpgkey : fetch/generate backup RSA key and output all pieces'
    debug:
      msg: "{{ lookup('ahvl_gpgkey', gpgkey_keyset='backup', gpgkey_type='rsa', gpgkey_fullname='bckp_rsa', gpgkey_email='myemail', gpgkey_comment=inventory_hostname, in=item, out='plaintext') }}"
    loop: "{{ gpgkey_backup_ins }}"
```

#### Credentials

```yaml
---
# playbook to demonstrate ahvl_credential

- hosts: localhost
  gather_facts: no

  vars:
    credential_outs:
      - plaintext
      - hexsha256
      - hexsha512
      - sha256crypt
      - sha512crypt
      - phpass
      - mysql41
      - postgresmd5
      - pbkdf2sha256
      - pbkdf2sha512
      - argon2
      - grubpbkdf2sha512

  tasks:

  # search path used for vault will be [credentials/transip]
  - name: 'ahvl_password : find credential; will fail if it does not exist'
    debug:
      msg: "{{ lookup('ahvl_credential', find='transip', in='apikeyxyz', out=item) }}"
    loop: "{{ credential_outs }}"
```



## Configuration Options

To give you maximum flexibility in configuring the behaviour of these lookup plugins, there are several ways you can set the option values, one taking precedence over the other. The order in which they are processed is as follows. The lowest number will have the highest priority. Obviously, the variable precedence as defined in Ansible also applies. Consult the [Ansible docs](https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html#variable-precedence-where-should-i-put-a-variable) for more information.


| Priority | Method                | Example                                                          | Comments                                   |
|----------|-----------------------|------------------------------------------------------------------|--------------------------------------------|
| 1        | Lookup arguments      | `lookup('ahvl_password', find='mysql' in='myuser', out='mysql41')` | |
| 2        | Environment variables | `AHVL_CONNECTION_AHVL_TOKEN=http://localhost:8200` | |
| 3        | Prefixed variables    | `ahvl_connection_ahvl_url:'http://localhost:8200'` | |
| 4        | Nested variables      | `ahvl_connection:`<br>&nbsp;&nbsp;`ahvl_url: 'http://localhost:8200'` | |
| 5        | ansible.cfg           | `[ahvl_connection]`<br>`ahvl_token: 'yourtoken'` | Only supported for AHVL Connection details |
| 6        | Defaults              | `None` | Hardcoded in the lookup plugin |


#### ahvl Vault connection options

Every lookup will generate at least a single request to the HashiCorp Vault. In case a new secret has been generated, or a search path doesn't exist yet, more than one request will be made. The following connection details can be set:

| Option name                  | Required | Value type | Possible values                   | Default value           | Comment |
|------------------------------|:--------:|:----------:|-----------------------------------|-------------------------|---------|
| ahvl_url                     | yes      | string     | `protocol://fqdn:port`            | http://localhost:8200   | |
| ahvl_auth_method             | yes      | string     | `token` / `userpass` / `ldap` / `approle` | `token`         | vault authentication method |
| ahvl_namespace               | no       | string     |                                   | `None`                  | vault secret namespace |
| ahvl_validate_certs          | no       | boolean    | `True` / `False`                  | `True`                  | validate vault certificates; set to False if not using an https connection; if you're using self-signed certificates provide the root certificate in ahvl_cacert instead |
| ahvl_mount_point             | no       | string     |                                   | `secret`                | vault secret mount point |
| ahvl_cacert                  | no       | path       | `/fullpath/to/file.crt`           | `None`                  | (self-signed) certificate to verify https connection |
| ahvl_username                | no       | string     |                                   | `None`                  | vault login username; required if auth_method is userpass/ldap |
| ahvl_password                | no       | string     |                                   | `None`                  | vault login password; required if auth_method is userpass/ldap; it is strongly recommended to only set the password using the environment variable AHVL_CONNECTION_AHVL_PASSWORD |
| ahvl_role_id                 | no       | string     |                                   | `None`                  | vault login role id; required if auth_method is approle |
| ahvl_secret_id               | no       | string     |                                   | `None`                  | vault login secret id; required if auth_method is approle |
| ahvl_token                   | no       | string     |                                   | `None`                  | vault token; required if auth_method is token; it is strongly recommended to only set the token using the environment variable AHVL_CONNECTION_AHVL_TOKEN! |


#### ahvl General options

These options apply to all lookup plugins and can (or sometimes must) be set for each lookup. With the exception of the ahvl_tmppath, these options cannot be set globally.

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| hostname                     | yes      | fqdn       |                             | `inventory_hostname`         | The hostname can/will be used as part of the search path |
| ahvl_tmppath                 | no       | path       | `/fullpath/to/tmpdir`       | ansible generated tmp path | **BEWARE:** The tmppath **WILL BE DELETED AT THE END OF EACH LOOKUP**! To be safe, leave this setting empty; ansible will provide a random temporary folder which can be safely deleted. |
| find                         | yes      | string     |                             | `None`                       | The find parameter is used as part of the search path |
| in                           | yes      | string     | depends on lookup plugin    | `None`                       | At the given search path, determine which key to look for |
| out                          | yes      | string     | `plaintext` / `hexsha256` / `hexsha512` / `sha256crypt` / `sha512crypt` / `grubpbkdf2sha512` / `phpass` / `mysql41` / `postgresmd5` / `pbkdf2sha256` / `pbkdf2sha512` / `argon2` | `hexsha512` | The format in which the secret will be returned. The hex*, mysql41 and postgresmd5 formats provide a hash, the sha* and phpass functions will give you a salted hash. Each hostname/secret/hash combination will have a unique salt and the salt will also be stored in vault to make sure each subsequent playbook run will not generate a new salt and thus result in a 'changed' state. For each hash function the correct salt is determined automatically based on best practices. |
| path                         | no       | string     | `{find}` / `{hostname}`           | depends on lookup plugin   | The actual search path used to find secret in vault. If not specified, it will be determined by the lookup plugin. When setting the path directly, you can use the variables {find} and {hostname} which will be replaced by the correct values prior to querying vault. |
| autogenerate                 | no       | boolean    | `True` / `False`                  | `True`                       | Whether or not to automatically generate new secrets when they could not be found in vault or when the latest version of the secret has been deleted |
| renew                        | no       | boolean    | `True` / `False`                  | `False`                      | Forces renewal of the secret, regardless of whether it already exists or not; will not change the behaviour of the autogenerate option. Be careful when using this, as it will be triggered for each and every lookup where this option is True, particularly in loops! |


#### ahvl Lookup Password options

###### General options

| Option name | Default value | Available options |
|-------------|---------------|-------------------|
| path | `hosts/{hostname}/{find}` | |

###### Lookup options

No additional options available, however, check the [ahvl Generate Password options](#ahvl-generate-password-options) section as well!


#### ahvl Lookup SSH Key options

###### General options

| Option name | Default value | Available options |
|-------------|---------------|-------------------|
| path | `sshkeys/{find}` |  |
| in | `None` | `private` / `password` / `private_keybits` / `private_keytype` / `private_pkcs8` / `private_openssh` / `private_putty` / `private_sshcom` / `public` / `public_pem` / `public_pkcs8` / `public_rfc4716` / `fingerprint_sha256` / `fingerprint_sha256_clean` / `fingerprint_sha256_art` / `fingerprint_md5` / `fingerprint_md5_clean` / `fingerprint_md5_art` / `fingerprint_putty` / `fingerprint_bubblebabble` / `fingerprint_bubblebabble_clean` |

###### Lookup options

No additional options available, however, check the [ahvl Generate SSH Key options](#ahvl-generate-ssh-key-options) section as well!


#### ahvl Lookup SSH Hostkey options

###### General options

| Option name | Default value | Available options |
|-------------|---------------|-------------------|
| path | `hosts/{hostname}/sshhostkeys/{find}` |  |
| find | `None` | `ed25519` / `rsa` |
| in | `None` | `private` / `private_keybits` / `private_keytype` / `fingerprint_sha256` / `fingerprint_sha256_clean` / `fingerprint_sha256_art` / `fingerprint_md5` / `fingerprint_md5_clean` / `fingerprint_md5_art` / `fingerprint_bubblebabble` / `fingerprint_bubblebabble_clean` / `dns_sha1` / `dns_sha1_clean` / `dns_sha256` / `dns_sha256_clean` / `public` |

###### Lookup options

No additional options available, however, check the [ahvl Generate SSH Hostkey options](#ahvl-generate-ssh-hostkey-options) section as well!


#### ahvl Lookup GPG Key options

###### General options

| Option name | Default value | Available options |
|-------------|---------------|-------------------|
| path | `gpgkeys/{find}` |  |
| find | `None` | when `gpgkey_keyset=backup` : `ed25519` / `rsa` |
| in | `None` | when `gpgkey_keyset=regular` :<br>`master_cert_pub_key_armored` / `master_cert_sec_key_armored` / `master_cert_sec_keytype` / `master_cert_sec_keyuid` / `master_cert_sec_password` / `master_cert_sec_fingerprint` / `master_cert_sec_keycurve` / `master_cert_sec_keygrip` / `master_cert_sec_keybits` / `master_cert_sec_creationdate` / `master_cert_sec_keyid` / `master_cert_sec_expirationdate` / `subkey_sign_sec_key_armored` / `subkey_sign_sec_fingerprint` / `subkey_sign_sec_keycurve` / `subkey_sign_sec_keygrip` / `subkey_sign_sec_keybits` / `subkey_sign_sec_creationdate` / `subkey_sign_sec_keyid` / `subkey_sign_sec_expirationdate` / `subkey_encr_sec_key_armored` / `subkey_encr_sec_fingerprint` / `subkey_encr_sec_keycurve` / `subkey_encr_sec_keygrip` / `subkey_encr_sec_keybits` / `subkey_encr_sec_creationdate` / `subkey_encr_sec_keyid` / `subkey_encr_sec_expirationdate` / `subkey_auth_sec_key_armored` / `subkey_auth_sec_fingerprint` / `subkey_auth_sec_keycurve` / `subkey_auth_sec_keygrip` / `subkey_auth_sec_keybits` / `subkey_auth_sec_creationdate` / `subkey_auth_sec_keyid` / `subkey_auth_sec_expirationdate`<br><br>when `gpgkey_keyset=backup` :<br>`sign_master_cert_pub_key_armored` / `sign_master_cert_sec_key_armored` / `sign_master_cert_sec_keytype` / `sign_master_cert_sec_keyuid` / `sign_master_cert_sec_password` / `sign_master_cert_sec_fingerprint` / `sign_master_cert_sec_keycurve` / `sign_master_cert_sec_keygrip` / `sign_master_cert_sec_keybits` / `sign_master_cert_sec_creationdate` / `sign_master_cert_sec_keyid` / `sign_master_cert_sec_expirationdate` / `sign_subkey_sign_sec_key_armored` / `sign_subkey_sign_sec_fingerprint` / `sign_subkey_sign_sec_keycurve` / `sign_subkey_sign_sec_keygrip` / `sign_subkey_sign_sec_keybits` / `sign_subkey_sign_sec_creationdate` / `sign_subkey_sign_sec_keyid` / `sign_subkey_sign_sec_expirationdate` / `encr_master_cert_pub_key_armored` / `encr_master_cert_sec_key_armored` / `encr_master_cert_sec_keytype` / `encr_master_cert_sec_keyuid` / `encr_master_cert_sec_password` / `encr_master_cert_sec_fingerprint` / `encr_master_cert_sec_keycurve` / `encr_master_cert_sec_keygrip` / `encr_master_cert_sec_keybits` / `encr_master_cert_sec_creationdate` / `encr_master_cert_sec_keyid` / `encr_master_cert_sec_expirationdate` / `encr_subkey_encr_sec_key_armored` / `encr_subkey_encr_sec_fingerprint` / `encr_subkey_encr_sec_keycurve` / `encr_subkey_encr_sec_keygrip` / `encr_subkey_encr_sec_keybits` / `encr_subkey_encr_sec_creationdate` / `encr_subkey_encr_sec_keyid` / `encr_subkey_encr_sec_expirationdate` |

###### Lookup options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| gpgkey_fullname | yes | string | | `None` |  full name for key |
| gpgkey_email | yes | string | | `None` |  email for key |
| gpgkey_comment | no | string | | `None` |  comment for key; if not provided will default to `hostname` |
| gpgkey_uid | no | string | | `None` |  uid for key; if not provided will default to `<gpgkey_fullname>_<gpgkey_comment>_<gpgkey_email>` |
| gpgkey_keyset | yes | string | `regular` / `backup` | `regular` | keyset to generate |

No additional options available, however, check the [ahvl Generate GPG Key options](#ahvl-generate-gpg-key-options) section as well!


#### ahvl Lookup Credential options

###### General options

| Option name | Default value | Available options |
|-------------|---------------|-------------------|
| path | `credentials/{find}` | |

###### Lookup options

No additional options available.


#### ahvl Generate Password options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| pwd_type | yes | string | `word` / `phrase` | `word` | type of password to generate; word or phrase |
| pwd_entropy | yes | string | `weak` / `fair` / `strong` / `secure` | `secure` | strength of password; check passlib docs for allowed values |
| pwd_length | no | integer |  | `32` | length of password; if omitted is auto calculated based on entropy |
| pwd_chars | no | string |  | `None` | specific string of characters to use when generating passwords |
| pwd_charset | no | string | `ascii_62` / `ascii_50` / `ascii_72` / `hex` | `ascii_72` | specific charset to use when generating passwords |
| pwd_words | no | string |  | `None` | list of words to use when generating passphrase |
| pwd_wordset | no | string | `eff_long` / `eff_short` / `eff_prefixed` / `bip39` | `eff_long` | predefined list of words to use when generating passphrase; check passlib docs for allowed values |
| pwd_sep | no | string |  | ` ` | word separator for passphrase |


#### ahvl Generate SSH Key options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| sshkey_type | yes | string | `ed25519` / `rsa` | `ed25519` | type of ssh key to generate |
| sshkey_bits | yes | integer |  | `4096` | number of bits for ssh key |
| sshkey_username | no | string |  | `None` | ssh key username; defaults to `find` if not provided |
| sshkey_comment | no | string |  | `None` | sshkey comment; defaults to `username` if not provided |
| sshkey_bin_keygen | yes | path |  | `None` | full path to ssh-keygen binary; attempts to find `ssh-keygen` if not provided |
| sshkey_bin_openssl | no | path |  | `None` | full path to puttygen binary, for pkcs8 key format; attempts to find `openssl` if not provided |
| sshkey_bin_puttygen | no | path |  | `None` | full path to puttygen binary; attempts to find `puttygen` when not provided |
| sshkey_pkcs8_enabled | no | boolean |  | `False` | use openssl to convert keys to pkcs8 compatible keys |
| sshkey_putty_enabled | no | boolean |  | `False` | use puttygen to convert keys to putty/sshcom compatible keys |


#### ahvl Generate SSH Hostkey options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| sshhostkey_type | yes | string | `ed25519` / `rsa` | `None` | type of keys to generate when generating hostkeys |
| sshhostkey_strength | yes | string | `medium` / `strong` | `strong` | hostkey strength; see gen_sshhostkey function for actual values |
| sshhostkey_comment | no | string |  | `None` | sshhostkey comment |
| sshhostkey_bin_keygen | yes | path |  | `None` | full path to ssh-keygen binary; attempts to find `ssh-keygen` if not provided |

#### ahvl Generate GPG Key options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| gpgkey_conf | no | list | described in gpg manpage | `['keyid-format 0xlong', 'with-fingerprint', 'personal-cipher-preferences AES256', 'personal-digest-preferences SHA512', 'cert-digest-algo SHA512']` | Contains the options which will be written to gpg.conf when manipulating keys. It will always be appended with the key preferences as defined in `gpgkey_pref` |
| gpgkey_pref | yes | list | described in gpg manpage | `['SHA512', 'SHA384', 'SHA256', 'SHA224', 'AES256', 'AES192', 'ZLIB', 'BZIP2', 'ZIP', 'Uncompressed']` | Preferences regarding ciphers, digests and algorithms |
| gpgkey_digest | no | string |  | `SHA512` | used with gpg option --digest-algo |
| gpgkey_s2k_cipher | no | string |  | `AES256` | used with gpg option --s2k-cipher-algo |
| gpgkey_s2k_digest | no | string |  | `SHA512` | used with gpg option --s2k-digest-algo |
| gpgkey_s2k_mode | no | integer |  | `3` | used with gpg option --s2k-mode |
| gpgkey_s2k_count | no | integer |  | `65011712` | used with gpg option --s2k-count; must be between 1024-65011712 inclusive |
| gpgkey_fullname | yes | string |  | `None` | concatenated into a uid like; fullname (comment) <email> |
| gpgkey_email | yes | string |  | `None` | concatenated into a uid like; fullname (comment) <email> |
| gpgkey_comment | no | string |  | `None` | concatenated into a uid like; fullname (comment) <email> |
| gpgkey_uid | yes | string |  | `None` | the uid |
| gpgkey_expirationdate | yes | string |  | `0` | key expiration date in the format of [YYYY-MM-DD], [YYYYMMDDThhmmss], seconds=(int)|(int)[d|w|m|y]|0 |
| gpgkey_bits | yes | integer |  | `4096` | key length; only used by RSA keys; will be added to the gpgkey_algo variable for RSA keys |
| gpgkey_type | yes | string | `ed25519` / `rsa` | `ed25519` | main key type to use for all 4 keys (master + 3 subkeys); supported are rsa|ed25519 |
| gpgkey_bin | yes | path |  | `None` | full path to gpg binary |
| gpgkey_keyset | yes | string | `regular` / `backup` | `regular` | set of keys to generate; regular or backup (i.e. for duplicity) |


#### ahvl Generate Salt options

| Option name                  | Required | Value type | Possible values             | Default value              | Comment |
|------------------------------|:--------:|:----------:|-----------------------------|----------------------------|---------|
| salt_chars | yes | string | `itoa64` / `alnum` | `itoa64` | Set of characters to use when generating salts; alnum is Alpha-numeric. while itoa64 adds the `.` and `/` characters to the `alnum` set |

## Update ahvl package instructions

* create a working directory `mkdir /opt/ahvl && cd /opt/ahvl`
* make sure twine is installed `pip install twine`
* make sure your github SSH key is available
* login to github `ssh -T git@github.com`
* clone repository `git clone git://github.com/netson/ahvl`
* set remote origin `git remote set-url origin git@github.com:netson/ahvl.git`
* make changes as needed
* remove any dist folder that may exist `rm -rf ./dist && rm MANIFEST`
* determine next PyPi package version number, look at `https://github.com/netson/ahvl/releases`
* change the `version` and `download_url` in `setup.py`
* commit changes to git `git add . && git commit -m "commit message"`
* push to master `git push origin master`
* create a new release on github with the same version number as in `download_url`
* create PyPi source distribution `python setup.py sdist`
* test package upload using twine `twine upload --repository-url https://test.pypi.org/legacy/ dist/*`
* verify test results on `https://test.pypi.org/manage/projects/`
* upload package to PyPi using twine `twine upload dist/*`
* enter your `username` and `password`
* DONE! :-)
