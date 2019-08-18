#
# import modules
#
from ahvl.options.base import OptionsBase
from ahvl.helper import AhvlMsg, AhvlHelper

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# OptionsHashiVault
#
class OptionsHashiVault(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_connection"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return None


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {
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


    # calculate any remaining options
    def get_appended(self):

        # return list of overide options or calculated options
        return {}


    # set required options
    def get_required(self):

        # return required options - list
        return [
            'ahvl_url',
            'ahvl_auth_method',
        ]


    # validate all set options
    def validate(self):

        # write shorthand
        o = self.options

        # sanity checks
        if o['ahvl_auth_method'] == 'token' and hlp.isempty(o['ahvl_token']):
            msg.fail("you have selected token authentication for vault, but the token is missing", o)

        # user/pass for ldap and userpass authentication
        if (o['ahvl_auth_method'] == "ldap" or o['ahvl_auth_method'] == 'userpass') \
        and (hlp.isempty(o['ahvl_username']) or hlp.isempty(o['ahvl_password'])):
            msg.fail("authentication method [{}] requires a username and password".format(o['ahvl_auth_method']), o)

        # role_id/secret_id for approle authentication
        if o['ahvl_auth_method'] == 'approle' and (hlp.isempty(o['ahvl_role_id']) or hlp.isempty(o['ahvl_secret_id'])):
            msg.fail("authentication method app role requires a role_id and secret_id", o)
