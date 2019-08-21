#
# import modules
#
from ahvl.helper import AhvlMsg, AhvlHelper
from ansible.module_utils.parsing.convert_bool import BOOLEANS, BOOLEANS_FALSE, BOOLEANS_TRUE, boolean
import hvac

#
# message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# HashiVault
#
class HashiVault:

    #
    # set options
    #
    def setopts(self, options):
        self.opts = options

    #
    # connect to vault
    #
    def connect(self, lookup_plugin):

        # check if certificate validation is needed
        self.verify = self.boolean_or_cacert()
        msg.vvvv("verifying vault certificates [{}]".format(self.verify))

        # set vault connection dict
        vault_dict = {
            'url' : self.opts.get('ahvl_url'),
            'verify' : self.verify,
        }

        # set namespace
        if not hlp.isempty(self.opts.get('ahvl_namespace')):
            vault_dict['namespace'] = self.opts.get('ahvl_namespace')

        # set token
        if self.opts.get('ahvl_auth_method') == 'token':
            vault_dict['token'] = self.opts.get('ahvl_token')

        # connect
        self.client = hvac.Client(**vault_dict)

        #
        # If a particular backend is asked for (and its method exists) we call it, otherwise drop through to using
        # token auth. This means if a particular auth backend is requested and a token is also given, then we
        # ignore the token and attempt authentication against the specified backend.
        #
        # to enable a new auth backend, simply add a new 'def auth_<type>' method below.
        #
        if self.opts.get('ahvl_auth_method') != 'token':
            try:
                # prefixing with auth_ to limit which methods can be accessed
                getattr(self, 'auth_' + self.opts.get('ahvl_auth_method'))
            except AttributeError:
                msg.fail("authentication method [{}] not supported.".format(self.opts.get('ahvl_auth_method')))

        # check if we're authenticated
        if not self.client.is_authenticated():
            msg.fail("invalid hashicorp vault token specified for lookup")

        msg.vvvv("connection authenticated using [{}]".format(self.opts.get('ahvl_auth_method')))


    def get(self, path, key):

        msg.vvvv("getting vault data from path [{}] and key [{}] at mountpoint [{}]".format(path, key, self.opts.get('ahvl_mount_point')))

        # wrap in try/except block to catch hvac.exceptions.InvalidPath exception when the path does not exist yet
        try:
            # read data from vault with the given mount point, path and key
            data = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.opts.get('ahvl_mount_point'),
            )

        # create the path so it can be written to
        except hvac.exceptions.InvalidPath:

            # using None as this is used to check if the secret exists in the find_ functions
            secret_dict = { key : None }
            ret = self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_dict,
                mount_point=self.opts.get('ahvl_mount_point'),
            )
            data = None
            pass

        # check if requested path/key exists
        if data is None or ('data' in data and 'data' in data['data'] and key not in data['data']['data']):
            return None

        # return requested key
        return data['data']['data'][key]


    def set(self, path, key, secret):

        msg.vvvv("setting vault data in path [{}] and key [{}] at mountpoint [{}]".format(path, key, self.opts.get('ahvl_mount_point')))

        # set or update secret; since it's versioned, we won't lose any previous values
        secret_dict = { key: secret }

        # using create_or_update overwrites the entire secret
        ret = self.client.secrets.kv.v2.patch(
            path=path,
            secret=secret_dict,
            mount_point=self.opts.get('ahvl_mount_point'),
        )


    def setdict(self, path, secrets):

        msg.vvvv("setting vault data dict in path [{}] at mountpoint [{}]".format(path, self.opts.get('ahvl_mount_point')))

        # using create_or_update overwrites the entire secret
        ret = self.client.secrets.kv.v2.patch(
            path=path,
            secret=secrets,
            mount_point=self.opts.get('ahvl_mount_point'),
        )

    def auth_userpass(self):

        msg.vvvv("attempt to authenticate to vault using [userpass]")

        # check mount point
        if hlp.isempty(self.opts.get('ahvl_mount_point')):
            self.opts.set('ahvl_mount_point', 'userpass')

        # authenticate
        self.client.auth_userpass(self.opts.get('ahvl_username'), self.opts.get('ahvl_password'), mount_point=self.opts.get('ahvl_mount_point'))

    def auth_ldap(self):

        msg.vvvv("attempt to authenticate to vault using [ldap]")

        # check mount point
        if hlp.isempty(self.opts.get('ahvl_mount_point')):
            self.opts.set('ahvl_mount_point', 'ldap')

        # authenticate
        self.client.auth_ldap(self.opts.get('ahvl_username'), self.opts.get('ahvl_password'), mount_point=self.opts.get('ahvl_mount_point'))

    def auth_approle(self):

        msg.vvvv("attempt to authenticate to vault using [approle]")

        # authenticate
        self.client.auth_approle(self.opts.get('ahvl_role_id'), self.opts.get('ahvl_secret_id'))

    def boolean_or_cacert(self):

        validate_certs = boolean(self.opts.get('ahvl_validate_certs'), strict=False)
        '''' return a bool or cacert '''
        if validate_certs is True:
            if self.opts.get('ahvl_cacert') != '':
                return self.opts.get('ahvl_cacert')
            else:
                return True
        else:
            return False
