# python 3 headers, required if submitting to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.0',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = """
    lookup: gpgkey
    version_added: "1.0"
    author:
      - Rinck H. Sonnenberg <r.sonnenberg@netson.nl>
    short_description: retrieve or generate an GPG key, stored in hashicorp vault

    description:
      - Generates an GPG key and allows to retrieve it in various formats.
      - If the gpgkey existed previously, it will retrieve its value.
      - You can choose which type of return value you wish to receive; various options are available (such as publickey, privatekey, etc).
      - "Options can be set in 5 different places and will be parsed in the following order until a value is found:"
      - 1. Check if options have been set as function arguments;
      - 2. Check if options have been set as environment variable;
      - 3. Check if options have been set as playbook variables;
      - 4. Check if options have been set as nested playbook variables;
      - 5. Check if options have been set using ansible-doc (only applicable for Vault Connection options and tmp path);
      - 6. Use the default value.

    options:
      ahvl_url:
        description:
           - "full URL to HashiCorp Vault including protocol and port"
           - "variable names: ahvl_connection_ahvl_url / ahvl_connection['ahvl_url']"
           - "os environment name: AHVL_CONNECTION_AHVL_URL"
        ini:
          - section: ahvl_connection
            key: ahvl_url
        required: False
        type: string
        version_added: 1.0
      ahvl_auth_method:
        description:
           - "vault authentication method"
           - "variable names: ahvl_connection_ahvl_auth_method / ahvl_connection['ahvl_auth_method']"
           - "os environment name: AHVL_CONNECTION_AHVL_AUTH_METHOD"
        ini:
          - section: ahvl_connection
            key: ahvl_auth_method
        required: False
        type: string
        version_added: 1.0
      ahvl_validate_certs:
        description:
           - "validate vault certificates"
           - "variable names: ahvl_connection_ahvl_validate_certs / ahvl_connection['ahvl_validate_certs']"
           - "os environment name: AHVL_CONNECTION_AHVL_VALIDATE_CERTS"
        ini:
          - section: ahvl_connection
            key: ahvl_validate_certs
        required: False
        type: boolean
        version_added: 1.0
      ahvl_cacert:
        description:
           - "vault login certificate"
           - "variable names: ahvl_connection_ahvl_cacert / ahvl_connection['ahvl_cacert']"
           - "os environment name: AHVL_CONNECTION_AHVL_CACERT"
        ini:
          - section: ahvl_connection
            key: ahvl_cacert
        required: False
        type: path
        version_added: 1.0
      ahvl_namespace:
        description:
           - "secret namespace"
           - "variable names: ahvl_connection_ahvl_namespace / ahvl_connection['ahvl_namespace']"
           - "os environment name: AHVL_CONNECTION_AHVL_NAMESPACE"
        ini:
          - section: ahvl_connection
            key: ahvl_namespace
        required: False
        type: string
        version_added: 1.0
      ahvl_mount_point:
        description:
           - "vault secret mount point"
           - "variable names: ahvl_connection_ahvl_mount_point / ahvl_connection['ahvl_mount_point']"
           - "os environment name: AHVL_CONNECTION_AHVL_MOUNT_POINT"
        ini:
          - section: ahvl_connection
            key: ahvl_mount_point
        required: False
        type: string
        version_added: 1.0
      ahvl_username:
        description:
           - "vault login username"
           - "variable names: ahvl_connection_ahvl_username / ahvl_connection['ahvl_username']"
           - "os environment name: AHVL_CONNECTION_AHVL_USERNAME"
        ini:
          - section: ahvl_connection
            key: ahvl_username
        required: False
        type: string
        version_added: 1.0
      ahvl_password:
        description:
           - "vault login password"
           - "variable names: ahvl_connection_ahvl_password / ahvl_connection['ahvl_password']"
           - "os environment name: AHVL_CONNECTION_AHVL_PASSWORD"
        ini:
          - section: ahvl_connection
            key: ahvl_password
        required: False
        type: string
        version_added: 1.0
      ahvl_role_id:
        description:
           - "vault login role id"
           - "variable names: ahvl_connection_ahvl_role_id / ahvl_connection['ahvl_role_id']"
           - "os environment name: AHVL_CONNECTION_AHVL_ROLE_ID"
        ini:
          - section: ahvl_connection
            key: ahvl_role_id
        required: False
        type: string
        version_added: 1.0
      ahvl_secret_id:
        description:
           - "vault login secret id"
           - "variable names: ahvl_connection_ahvl_secret_id / ahvl_connection['ahvl_secret_id']"
           - "os environment name: AHVL_CONNECTION_AHVL_SECRET_ID"
        ini:
          - section: ahvl_connection
            key: ahvl_secret_id
        required: False
        type: string
        version_added: 1.0
      ahvl_token:
        description:
           - "vault token"
           - "variable names: ahvl_connection_ahvl_token / ahvl_connection['ahvl_token']"
           - "os environment name: AHVL_CONNECTION_AHVL_TOKEN"
        ini:
          - section: ahvl_connection
            key: ahvl_token
        required: False
        type: string
        version_added: 1.0
      ahvl_tmppath:
        description:
           - "vault token"
           - "variable names: ahvl_connection_ahvl_tmppath / ahvl_connection['ahvl_tmppath']"
           - "os environment name: AHVL_CONNECTION_AHVL_TMPPATH"
        default: ""
        ini:
          - section: ahvl_connection
            key: ahvl_tmppath
        required: False
        type: tmppath
        version_added: 1.0
"""

EXAMPLES = """
- hosts: localhost
  gather_facts: no

  vars:
    netson.ahvl.sshkey:
      basepath: "hosts/{}".format(self.hostname)                # basepath
      path: None                                                # path to find secret
      path: None                                            # path to find secret; set in validate()
      key: None                                                 # key of secret
      ret: None                                                 # return hash/plain
      renew: no                                                 # force generating a new password regardless if it exists or not

    ahvl_connection:
      url: 'https://192.168.8.8:8200'                           # hashi vault url i.e. https://fqdn:8200
      auth_method: 'token'                                      # authentication method
      validate_certs: yes                                       # validate vault certificates
      cacert: '/usr/local/share/ca-certificates/Netson_CA.crt'  # vault login certificate
      namespace: None                                           # secret namespace
      mount_point: 'secret'                                     # vault secret mount point
      username: None                                            # vault login username
      password: None                                            # vault login password
      role_id: None                                             # vault login role id
      secret_id: None                                           # vault login secret id
      token: None                                               # vault token

    ahvl_generate_salt:
      key: None                                                 # lookup key
      ret: None                                                 # return method; used to generate unique salt for each
      chars: 'itoa64'                                           # salt charset

    ahvl_generate_password:
      type: 'word'                                              # type of password to generate; word or phrase
      entropy: 'secure'                                         # strength of password; check passlib docs for allowed values
      length: 32                                                # length of password; if omitted is auto calculated based on entropy
      chars: None                                               # specific string of characters to use when generating passwords
      charset: 'ascii_72'                                       # specific charset to use when generating passwords
      words: None                                               # list of words to use when generating passphrase
      wordset: 'eff_long'                                       # predefined list of words to use when generating passphrase; check passlib docs for allowed values
      sep: ' '                                                  # word separator for passphrase

    password_outs:
      - plaintext
      - hexsha256
      - hexsha512
      - sha256crypt
      - sha512crypt
      - phpass
      - mysql41
      - postgresmd5
      - onetime

  # show all different ahvl lookups
  tasks:

  - name: 'ahvl_sshkey : test lookup'
    debug:
      msg: "{{ lookup('netson.ahvl.sshkey', path='mysql', key='myusr1', ret=item) }}"
    loop: "{{ password_outs }}"
"""

RETURN = """
  _raw:
    description:
      - the requested password, either in plaintext or hashed using the requested method
"""

#
# ansible modules are loaded in the AhvlLookup module
#
from ansible_collections.netson.ahvl.plugins.module_utils.lookup import AhvlLookup
from ansible_collections.netson.ahvl.plugins.module_utils.helper import AhvlMsg, AhvlHelper

#
# message/helper
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# look up module
#
class LookupModule(AhvlLookup):

    #
    # method called by ansible when running the module
    #
    def run(self, terms, variables=None, **kwargs):

        # initialize and load options
        self.initialize(variables, **kwargs)
        self.setopts("OptionsLookupGPGKey")

        # return value
        return self.return_secret('gpgkey', self.opts)
