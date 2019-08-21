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
# OptionsLookupSSHKey
#
class OptionsLookupSSHKey(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_sshkey"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return "sshkeys/{find}"


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {
            'sshkey_username'   : None,                         # username for key
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        find            = o['find']
        sshkey_username = o['sshkey_username']

        # set username/find
        if hlp.isempty(find):
            find            = sshkey_username
        if hlp.isempty(sshkey_username):
            sshkey_username = find

        # return list of overide options or calculated options
        return {
            'find'              : find,
            'sshkey_username'   : sshkey_username,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['sshkey_username',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set accepted values
        #
        allowed_in  = ["private", # default openssh output
                       "password",
                       "private_keybits",
                       "private_keytype",
                       "private_pkcs8",
                       "private_openssh", # new improved openssh output
                       "private_putty",
                       "private_sshcom", # commercial ssh from ssh.com
                       "public", # default openssh output
                       "public_pem",
                       "public_pkcs8",
                       "public_rfc4716",
                       "fingerprint_sha256",
                       "fingerprint_sha256_clean",
                       "fingerprint_sha256_art", # visual via ascii randomart
                       "fingerprint_md5",
                       "fingerprint_md5_clean",
                       "fingerprint_md5_art", # visual via ascii randomart
                       "fingerprint_putty",
                       "fingerprint_bubblebabble",
                       "fingerprint_bubblebabble_clean"]

        #
        # sanity checks
        #
        if o['in'] not in allowed_in:
            msg.fail("value for [in] parameter is invalid; [{}] given, but expected one of {}".format(o['in'], allowed_in))


        if hlp.isempty(o['path']):
            msg.fail("path is missing");
