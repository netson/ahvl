#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGenerateGPGKey
#
class OptionsGenerateGPGKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_generate_gpgkey"

    def required(self):

        # return list of required options
        return [
            'gpgkey_name',
            'gpgkey_type',
        ]

    def defaults(self):

        # set default option values
        options = {
            'gpgkey_name'          : None,                              # name of the key
            'gpgkey_email'         : None,                              # email address for the key
            'gpgkey_comment'       : None,                              # comment for the key; defaults to hostname
            'gpgkey_password_sign' : None,                              # sign key password
            'gpgkey_password_encr' : None,                              # encrypt key password
            'gpgkey_type'          : "rsa",                             # key type; either rsa or eddsa
            #'gpgkey_curve'         : "ed25519",                         # only used for keytype eddsa
            'gpgkey_length'        : "4096",                            # only used for keytype rsa
            'gpgkey_hostname'      : self.hostname,                     # hostname to be used
            'gpgkey_expiration'    : "0",                               # expiration for newly generated keys; either in ISO format YYYY-MM-DD or <int>[d|w|m|y]
                                     # cipher, hash and compression preferences for gpg
            'gpgkey_pref'          : "SHA512 SHA384 SHA256 SHA224 AES256 AES192 ZLIB BZIP2 ZIP Uncompressed",
            'gpgkey_binary'        : self.find_binary("gpg2"),           # full path to gpg binary
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
        allowed = ["rsa"] # "eddsa" not supported yet by python-gnupg

        #
        # set comment
        #
        if o['gpgkey_comment'] is None:
            self.set('gpgkey_comment', o['gpgkey_hostname'])

        #
        # sanity checks
        #
        if o['gpgkey_type'] not in allowed:
            self.error("invalid gpgkey type specified; recieved [{}] but expected on of {}".format(o['gpgkey_type'], allowed))
