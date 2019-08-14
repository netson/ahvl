#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGenerateSSHKey
#
class OptionsGenerateSSHKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_generate_sshkey"

    def required(self):

        # return list of required options
        return [
            'key_type',
            'key_username',
            'key_password',
            'ahvl_tmppath',
        ]

    def defaults(self):

        # set default option values
        options = {
            'key_type'       : "ed25519",                        # type of ssh key to generate
            'key_bits'       : "4096",                           # number of bits for ssh key
            'key_username'   : None,                             # ssh key username
            'key_password'   : None,                             # ssh key password
            'key_comment'    : None,                             # sshkey comment
            'bin_keygen'     : self.find_binary("ssh-keygen"),   # full path to ssh-keygen binary
            'bin_openssl'    : self.find_binary("openssl"),      # full path to puttygen binary, for pkcs8 key format
            'bin_puttygen'   : self.find_binary("puttygen"),     # full path to puttygen binary
            'pkcs8_enabled'  : False,                            # use openssl to convert keys to pkcs8 compatible keys
            'putty_enabled'  : False,                            # use puttygen to convert keys to putty/sshcom compatible keys
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
        # set comment
        #
        if o['key_comment'] is None:
            self.set('key_comment', self.get('key_username'))

        #
        # sanity checks
        #
        if o['key_type'] not in allowed:
            self.error("invalid sshkey type specified; recieved [{}] but expected on of {}".format(o['key_type'], allowed))

        # check ssh keytype and bits combo
        if (o['key_type'] == "rsa" and int(o['key_bits']) < 2048):
            self.error("sshkey of type [{}] cannot have less than [2048] bits; [{}] given".format(o['key_type'], o['key_bits']))

        # check binaries for openssl
        if (o['pkcs8_enabled'] and not (self.isfile(o['bin_openssl']) and self.isexecutablefile(o['bin_openssl']))):
            self.error("pkcs8 keytypes are enabled, but the openssl binary [{}] could not be found or is not executable".format(o['bin_openssl']))

        # check binaries for puttygen
        if (o['putty_enabled'] and not (self.isfile(o['bin_puttygen']) and self.isexecutablefile(o['bin_puttygen']))):
            self.error("putty keytypes are enabled, but the puttygen binary [{}] could not be found or is not executable".format(o['bin_puttygen']))
