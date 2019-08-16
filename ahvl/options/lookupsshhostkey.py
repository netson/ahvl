#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsLookupSSHHostKey
#
class OptionsLookupSSHHostKey(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_sshhostkey"

    def required(self):

        # return list of required options
        return [
            'hostkey_type',
            'key',
            'hostkey_hostname',
        ]

    def defaults(self):

        # set default option values
        options = {
            'basepath'          : "hosts/{}/sshhostkeys",                       # basepath; {} will be automatically replaced with the hostname
            'fullpath'          : None,                                         # path to find secret; set in validate()
            'key'               : None,                                         # which part to get (public, private, etc)
            'hostkey_type'      : None,                                         # type of key to get (rsa or ed25519)
            'fullkey'           : None,                                         # full name of the key to search for (i.e. <key>_<hostkey_type>)
            'hostkey_hostname'  : self.hostname,                                # hostname for the sshhostkeys
            'renew'             : False,                                        # force generating a new sshkey regardless if it exists or not
                                                                                # be careful with this setting, as it will renew on each iteration
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # set basepath, fullpath and fullkey
        #
        if o['basepath'].find("{}") != -1:
            self.set('basepath', o['basepath'].format(o['hostkey_hostname']))

        if self.isempty(o['fullpath']):
            self.set('fullpath', self.get('basepath'))

        if self.isempty(o['fullkey']):
            self.set('fullkey', "{}_{}".format(o['hostkey_type'], o['key']))

        #
        # set accepted values
        #
        allowed_hostkey = ["private", # key type is set by sshhostkey_type (default: ed25519)
                           "public",
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
                           "dns_sha256_clean"]

        allowed_types   = ["rsa",
                           "ed25519"]

        #
        # sanity checks
        #
        if o['key'] not in allowed_hostkey:
            self.error("value for key parameter is invalid; [{}] given, but expected one of {}".format(o['key'], allowed_key))

        if o['hostkey_type'] not in allowed_types:
            self.error("value for hostkey_type parameter is invalid; [{}] given, but expected one of {}".format(o['hostkey_type'], allowed_types))

        if self.isempty(o['basepath']) and self.isempty(o['fullpath']):
            self.error("either provide a basepath or provide the fullpath directly");
