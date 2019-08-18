#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsLookupSSHKey
#
class OptionsLookupSSHKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_sshkey"

    def required(self):

        # return list of required options
        return [
            'key_username',
            'key',
        ]

    def defaults(self):

        # set default option values
        options = {
            'basepath'      : "users",                      # basepath
            'key_username'  : None,                         # path to find secret
            'fullpath'      : None,                         # path to find secret; set in validate()
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
                "{}".format(o['key_username']).strip("/")
            )
            self.set('fullpath', fullpath)

        #
        # set accepted values
        #
        allowed_key = ["private", # default openssh output
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
        if o['key'] not in allowed_key:
            self.error("value for ret parameter is invalid; [{}] given, but expected one of {}".format(o['key'], allowed_key))

        if (self.isempty(o['basepath']) and self.isempty(o['key_username'])) or self.isempty(o['fullpath']):
            self.error("either provide a basepath and key_username, or provide the fullpath directly");
