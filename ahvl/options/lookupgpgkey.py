#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsLookupGPGKey
#
class OptionsLookupGPGKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_gpgkey"

    def required(self):

        # return list of required options
        return [
            'key',
            'gpgkey_name',
        ]

    def defaults(self):

        # set default option values
        options = {
            'basepath'      : "gpgkeys",                    # basepath
            'gpgkey_name'   : None,                         # name of the key to get
            'fullpath'      : None,                         # basepath
            'key'           : None,                         # which part to get (public, private, etc)
            'renew'         : False,                        # force generating a new sshkey regardless if it exists or not
                                                            # be careful with this setting, as it will renew on each iteration
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # set path
        #
        if self.isempty(o['fullpath']):
            fullpath = "{}/{}".format(
                "{}".format(o['basepath']).strip("/"),
                "{}".format(o['gpgkey_name']).strip("/")
            )
            self.set('fullpath', fullpath)

        #
        # set accepted values
        #
        allowed_key = ["private_encrypt",
                       "private_encrypt_keyid",
                       "private_encrypt_fingerprint",
                       "private_encrypt_createddate",
                       "private_encrypt_expirydate",
                       "private_sign",
                       "private_sign_keyid",
                       "private_sign_fingerprint",
                       "private_sign_createddate",
                       "private_sign_expirydate",
                       "public_encrypt",
                       "public_encrypt_keyid",
                       "public_encrypt_fingerprint",
                       "public_encrypt_createddate",
                       "public_encrypt_expirydate",
                       "public_sign",
                       "public_sign_keyid",
                       "public_sign_fingerprint",
                       "public_sign_createddate",
                       "public_sign_expirydate"]


        #
        # sanity checks
        #
        if o['key'] not in allowed_key:
            self.error("value for key parameter is invalid; [{}] given, but expected one of {}".format(o['key'], allowed_key))

        if (self.isempty(o['basepath']) and self.isempty(o['gpgkey_name'])) or self.isempty(o['fullpath']):
            self.error("either provide a basepath and gpgkey_name, or provide the fullpath directly");
