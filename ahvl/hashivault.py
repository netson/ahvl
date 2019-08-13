#
# hashi vault connect
#
class HashiVault:

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        #
        # options
        #
        self.opts = OptionsHashiVault(variables, lookup_plugin, **kwargs)

        #
        # sanity check
        #
        if not HAS_HVAC:
            self.error("the HVAC python library is needed, please pip install hvac")

        # check if certificate validation is needed
        self.verify = self.boolean_or_cacert()

        # set vault connection dict
        vault_dict = {
            'url' : self.opts.get('url'),
            'verify' : self.verify,
        }

        # set namespace
        if not self.opts.isempty(self.opts.get('namespace')):
            vault_dict['namespace'] = self.opts.get('namespace')

        # set token
        if self.opts.get('auth_method') == 'token':
            vault_dict['token'] = self.opts.get('token')

        # connect
        self.client = hvac.Client(**vault_dict)

        #
        # If a particular backend is asked for (and its method exists) we call it, otherwise drop through to using
        # token auth. This means if a particular auth backend is requested and a token is also given, then we
        # ignore the token and attempt authentication against the specified backend.
        #
        # to enable a new auth backend, simply add a new 'def auth_<type>' method below.
        #
        if self.opts.get('auth_method') != 'token':
            try:
                # prefixing with auth_ to limit which methods can be accessed
                getattr(self, 'auth_' + self.opts.get('auth_method'))
            except AttributeError:
                raise AnsibleError("authentication method [{}] not supported.".format(self.opts.get('auth_method')))

        # check if we're authenticated
        if not self.client.is_authenticated():
            raise AnsibleError("invalid hashicorp vault token specified for lookup")

    def get(self, fullpath, key):

        # wrap in try/except block to catch hvac.exceptions.InvalidPath exception when the path does not exist yet
        try:
            # read data from vault with the given mount point, path and key
            data = self.client.secrets.kv.v2.read_secret_version(
                path=fullpath,
                mount_point=self.opts.get('mount_point'),
            )

        # create the path so it can be written to
        except hvac.exceptions.InvalidPath:
            secret_dict = { key : None }
            ret = self.client.secrets.kv.v2.create_or_update_secret(
                path=fullpath,
                secret=secret_dict,
                mount_point=self.opts.get('mount_point'),
            )
            data = None
            pass

        # check if requested fullpath/key exists
        if data is None or ('data' in data and 'data' in data['data'] and key not in data['data']['data']):
            return None

        # return requested key
        return data['data']['data'][key]

    def set(self, fullpath, key, secret):

        # set or update secret; since it's versioned, we won't lose any previous values
        secret_dict = { key: secret }

        # using create_or_update overwrites the entire secret
        ret = self.client.secrets.kv.v2.patch(
            path=fullpath,
            secret=secret_dict,
            mount_point=self.opts.get('mount_point'),
        )

    def setdict(self, fullpath, secrets):

        # using create_or_update overwrites the entire secret
        ret = self.client.secrets.kv.v2.patch(
            path=fullpath,
            secret=secrets,
            mount_point=self.opts.get('mount_point'),
        )

    def auth_userpass(self):

        # check mount point
        if self.opts.isempty(self.opts.get('mount_point')):
            self.opts.set('mount_point', 'userpass')

        # authenticate
        self.client.auth_userpass(self.opts.get('username'), self.opts.get('password'), mount_point=self.opts.get('mount_point'))

    def auth_ldap(self):

        # check mount point
        if self.opts.isempty(self.opts.get('mount_point')):
            self.opts.set('mount_point', 'ldap')

        # authenticate
        self.client.auth_ldap(self.opts.get('username'), self.opts.get('password'), mount_point=self.opts.get('mount_point'))

    def auth_approle(self):

        # authenticate
        self.client.auth_approle(self.opts.get('role_id'), self.opts.get('secret_id'))

    def boolean_or_cacert(self):

        validate_certs = boolean(self.opts.get('validate_certs'), strict=False)
        '''' return a bool or cacert '''
        if validate_certs is True:
            if self.opts.get('cacert') != '':
                return self.opts.get('cacert')
            else:
                return True
        else:
            return False
