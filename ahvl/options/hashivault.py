#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsHashiVault
#
class OptionsHashiVault(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_connection"

    def required(self):

        # return list of required options
        return [
            'ahvl_url',
            'ahvl_auth_method',
        ]

    def defaults(self):

        # set default option values
        options = {
            'ahvl_url'             : 'http://localhost:8200',    # hashi vault url i.e. https://fqdn:8200
            'ahvl_auth_method'     : 'token',                    # authentication method
            'ahvl_namespace'       : None,                       # secret namespace
            'ahvl_validate_certs'  : True,                       # validate vault certificates
            'ahvl_mount_point'     : 'secret',                   # vault secret mount point
            'ahvl_cacert'          : None,                       # vault login certificate
            'ahvl_username'        : None,                       # vault login username
            'ahvl_password'        : None,                       # vault login password
            'ahvl_role_id'         : None,                       # vault login role id
            'ahvl_secret_id'       : None,                       # vault login secret id
            'ahvl_token'           : None,                       # vault token
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        # sanity checks
        if o['ahvl_auth_method'] == 'token' and self.isempty(o['ahvl_token']):
            self.error("you have selected token authentication for vault, but the token is missing")

        # user/pass for ldap and userpass authentication
        if (o['ahvl_auth_method'] == "ldap" or o['ahvl_auth_method'] == 'userpass') \
        and (self.isempty(o['ahvl_username']) or self.isempty(o['ahvl_password'])):
            self.error("authentication method [{}] requires a username and password".format(o['ahvl_auth_method']))

        # role_id/secret_id for approle authentication
        if o['ahvl_auth_method'] == 'approle' and (self.isempty(o['ahvl_role_id']) or self.isempty(o['ahvl_secret_id'])):
            self.error("authentication method app role requires a role_id and secret_id")
