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
# OptionsGenerateSSHKey
#
class OptionsGenerateSSHKey(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_generate_sshkey"


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
            'sshkey_type'           : "ed25519",                        # type of ssh key to generate
            'sshkey_bits'           : "4096",                           # number of bits for ssh key
            'sshkey_username'       : None,                             # ssh key username
            'sshkey_comment'        : None,                             # sshkey comment
            'sshkey_bin_keygen'     : None,                             # full path to ssh-keygen binary
            'sshkey_bin_openssl'    : None,                             # full path to puttygen binary, for pkcs8 key format
            'sshkey_bin_puttygen'   : None,                             # full path to puttygen binary
            'sshkey_pkcs8_enabled'  : False,                            # use openssl to convert keys to pkcs8 compatible keys
            'sshkey_putty_enabled'  : False,                            # use puttygen to convert keys to putty/sshcom compatible keys
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        find                = o['find']
        sshkey_comment      = o['sshkey_comment']
        sshkey_bin_keygen   = o['sshkey_bin_keygen']
        sshkey_bin_openssl  = o['sshkey_bin_openssl']
        sshkey_bin_puttygen = o['sshkey_bin_puttygen']
        sshkey_username     = o['sshkey_username']

        # set username/find
        if hlp.isempty(find):
            find            = sshkey_username
        if hlp.isempty(sshkey_username):
            sshkey_username = find

        # set comment
        if hlp.isempty(sshkey_comment):
            sshkey_comment = sshkey_username

        # determine binaries
        if hlp.isempty(sshkey_bin_keygen):
            sshkey_bin_keygen  = hlp.find_binary('ssh-keygen')
        if hlp.isempty(sshkey_bin_openssl) and o['sshkey_pkcs8_enabled']:
            sshkey_bin_openssl  = hlp.find_binary('openssl')
        if hlp.isempty(sshkey_bin_puttygen) and o['sshkey_putty_enabled']:
            sshkey_bin_puttygen  = hlp.find_binary('puttygen')

        # return list of overide options or calculated options
        return {
            'find'                  : find,
            'sshkey_comment'        : sshkey_comment,
            'sshkey_bin_keygen'     : sshkey_bin_keygen,
            'sshkey_bin_openssl'    : sshkey_bin_openssl,
            'sshkey_bin_puttygen'   : sshkey_bin_puttygen,
            'sshkey_username'       : sshkey_username,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['sshkey_type',
                'sshkey_bits',
                'sshkey_username',
                'sshkey_bin_keygen',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set accepted values
        #
        allowed_type = ["ed25519", "rsa"]

        #
        # sanity checks
        #
        if o['sshkey_type'] not in allowed_type:
            msg.fail("value for [sshkey_type] parameter is invalid; [{}] given, but expected one of {}".format(o['sshkey_type'], allowed_type))

        # check ssh keytype and bits combo
        if (o['sshkey_type'] == "rsa" and int(o['sshkey_bits']) < 2048):
            msg.fail("sshkey of type [{}] cannot have less than [2048] bits; [{}] given".format(o['sshkey_type'], o['sshkey_bits']))

        # check binaries for openssl
        if (o['sshkey_pkcs8_enabled'] and not (hlp.isfile(o['sshkey_bin_openssl']) and hlp.isexecutablefile(o['sshkey_bin_openssl']))):
            msg.fail("pkcs8 keytypes are enabled, but the openssl binary [{}] could not be found or is not executable".format(o['sshkey_bin_openssl']))

        # check binaries for puttygen
        if (o['sshkey_putty_enabled'] and not (hlp.isfile(o['sshkey_bin_puttygen']) and hlp.isexecutablefile(o['sshkey_bin_puttygen']))):
            msg.fail("putty keytypes are enabled, but the puttygen binary [{}] could not be found or is not executable".format(o['sshkey_bin_puttygen']))
