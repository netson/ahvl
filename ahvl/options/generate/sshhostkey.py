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
# OptionsGenerateSSHHostKey
#
class OptionsGenerateSSHHostKey(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_generate_sshhostkey"


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
            'sshhostkey_type'       : None,                             # type of keys to generate when generating hostkeys
            'sshhostkey_strength'   : "strong",                         # hostkey strength; see gen_sshhostkey function for actual values
            'sshhostkey_comment'    : None,                             # sshhostkey comment
            'sshhostkey_bin_keygen' : None,                             # full path to ssh-keygen binary
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        find                    = o['find']
        sshhostkey_type         = o['sshhostkey_type']
        sshhostkey_comment      = o['sshhostkey_comment']
        sshhostkey_bin_keygen   = o['sshhostkey_bin_keygen']

        # set find/sshhostkey_type
        if hlp.isempty(find):
            find = sshhostkey_type
        if hlp.isempty(sshhostkey_type):
            sshhostkey_type = find

        # set comment
        if hlp.isempty(sshhostkey_comment):
            sshhostkey_comment = o['hostname']

        # determine binary
        if hlp.isempty(sshhostkey_bin_keygen):
            sshhostkey_bin_keygen  = hlp.find_binary('ssh-keygen')

        # return list of overide options or calculated options
        return {
            'find'                  : find,
            'sshhostkey_type'       : sshhostkey_type,
            'sshhostkey_comment'    : sshhostkey_comment,
            'sshhostkey_bin_keygen' : sshhostkey_bin_keygen,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['sshhostkey_type',
                'sshhostkey_strength',
                'sshhostkey_comment',
                'sshhostkey_bin_keygen',
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
        if o['sshhostkey_type'] not in allowed_type or o['find'] not in allowed_type:
            msg.fail("value for [sshhostkey_type/find] parameter is invalid; [{}] given, but expected one of {}".format(o['sshhostkey_type'], allowed_type))
