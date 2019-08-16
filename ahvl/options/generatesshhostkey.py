#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGenerateSSHHostKey
#
class OptionsGenerateSSHHostKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_generate_sshkey"

    def required(self):

        # return list of required options
        return [
            'hostkey_type',
            'ahvl_tmppath',
            'hostkey_hostname',
        ]

    def defaults(self):

        # set default option values
        options = {
            'hostkey_type'      : "ed25519",                        # type of keys to generate when generating hostkeys
            'hostkey_strength'  : "strong",                         # hostkey strength; see gen_sshhostkey function for actual values
            'hostkey_comment'   : None,                             # sshhostkey comment
            'bin_keygen'        : self.find_binary("ssh-keygen"),   # full path to ssh-keygen binary
            'hostkey_hostname'  : self.hostname,                    # hostname for the sshhostkeys
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # set allowed key types
        # rsa1, dsa and ecdsa are explicitly not supported
        #
        allowed = ["ed25519", "rsa"]

        #
        # set basepath and comment
        #
        if o['hostkey_comment'] is None:
            self.set('hostkey_comment', o['hostkey_hostname'])

        #
        # sanity checks
        #
        if o['hostkey_type'] not in allowed:
            self.error("invalid sshhostkey type specified; recieved [{}] but expected on of {}".format(o['hostkey_type'], allowed))
