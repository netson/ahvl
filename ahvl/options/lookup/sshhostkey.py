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
# OptionsLookupSSHHostKey
#
class OptionsLookupSSHHostKey(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_sshhostkey"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return "hosts/{hostname}/sshhostkeys/{find}"


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {}


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # return list of overide options or calculated options
        return {}


    # set required options
    def get_required(self):

        # return required options - list
        return []


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set accepted values
        #
        allowed_in = ["private", # key type is set by sshhostkey_type (default: ed25519)
                      "private_keybits",
                      "private_keytype",
                      "fingerprint_sha256",
                      "fingerprint_sha256_clean",
                      "fingerprint_sha256_art",
                      "fingerprint_md5",
                      "fingerprint_md5_clean",
                      "fingerprint_md5_art",
                      "fingerprint_bubblebabble",
                      "fingerprint_bubblebabble_clean",
                      "dns_sha1",
                      "dns_sha1_clean",
                      "dns_sha256",
                      "dns_sha256_clean",
                      "public",
                     ]

        allowed_find = ["rsa", "ed25519"]

        #
        # sanity checks
        #
        if o['in'] not in allowed_in:
            msg.fail("value for [in] parameter is invalid; [{}] given, but expected one of {}".format(o['in'], allowed_in))

        if o['find'] not in allowed_find:
            msg.fail("value for [find] parameter is invalid; [{}] given, but expected one of {}".format(o['find'], allowed_find))

        if hlp.isempty(o['path']):
            msg.fail("path is missing");
