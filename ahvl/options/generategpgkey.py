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
            'gpgkey_uid',
        ]

    def defaults(self):

        #
        # KEY USAGE & ALGORITHMS:
        #
        # the value of the option [gpgkey_type] determines which combination of key-usage and algo are selected
        #
        # supported algorithms are:         rsa|ed25519|cv25519
        # supported key usage values are:   cert|sign|auth|encr
        #
        # supported combinations are:
        # +-----------+------+------+------+------+
        # | algorithm | cert | sign | auth | encr |
        # +-----------+------+------+------+------+
        # | rsa       | yes  | yes  | yes  | yes  |
        # | ed25519   | yes  | yes  | yes  | no   |
        # | cv25519   | no   | no   | no   | yes  |
        # +-----------+------+------+------+------+
        #
        # DEFAULT KEY SETUP:
        #
        # This module will always generate a set of 4 keys:
        # 1 master key [cert]
        # - subkey for signing [sign]
        # - subkey for authorization [auth]
        # - subkey for encryptio [encr]
        #

        # set default option values
        options = {
            # each list item is added to the gpg.conf for each run
            # the prefs are added seperately to the config file, based on the gpgkey_pref options
            'gpgkey_conf'           : ['keyid-format 0xlong',
                                       'with-fingerprint',
                                       'personal-cipher-preferences AES256',
                                       'personal-digest-preferences SHA512',
                                       'cert-digest-algo SHA512',
                                      ],

            # string of supported prefs as you would specify it in gpg.conf
            'gpgkey_pref'           : ['SHA512','SHA384','SHA256','SHA224','AES256','AES192','ZLIB','BZIP2','ZIP','Uncompressed'],

            'gpgkey_digest'         : 'SHA512',                 # used with gpg option --digest-algo
            'gpgkey_s2k_cipher'     : 'AES256',                 # used with gpg option --s2k-cipher-algo
            'gpgkey_s2k_digest'     : 'SHA512',                 # used with gpg option --s2k-digest-algo
            'gpgkey_s2k_mode'       : '3',                      # used with gpg option --s2k-mode
            'gpgkey_s2k_count'      : '65011712',               # used with gpg option --s2k-count; must be between 1024-65011712 inclusive
            'gpgkey_fullname'       : None,                     # concatenated into a uid like; fullname (comment) <email>
            'gpgkey_email'          : None,                     # concatenated into a uid like; fullname (comment) <email>
            'gpgkey_comment'        : self.hostname,            # concatenated into a uid like; fullname (comment) <email>
            'gpgkey_uid'            : None,                     # the uid
            'gpgkey_expire'         : '0',                      # key expiration date in the format of [YYYY-MM-DD], [YYYYMMDDThhmmss], seconds=(int)|(int)[d|w|m|y]|0
            'gpgkey_bits'           : '4096',                   # key length; only used by RSA keys; will be added to the gpgkey_algo variable for RSA keys
            'gpgkey_type'           : 'ed25519',                # main key type to use for all 4 keys (master + 3 subkeys); supported are rsa|ed25519
            'gpgkey_bin'            : self.find_binary("gpg2"), # full path to gpg binary
            'gpgkey_password'       : None,                     # password for the private master and subkeys; currently gpg does not support different passwords
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # add prefs to gpg conf
        #
        self.set('gpgkey_conf', o['gpgkey_conf'].append("default-preference-list {}".format(" ".join(o['gpgkey_pref']))))

        #
        # set find/uid
        #
        if not self.isempty(o['find']):
            self.set('gpgkey_uid', o['find'])

        if self.isempty(o['gpgkey_uid']):
            name    = "{}".format(o['gpgkey_fullname'])
            email    = " <{}>".format(o['gpgkey_email'])
            comment = " ({})".format(o['gpgkey_comment']) if not self.isempty(o['gpgkey_comment']) else ""
            uid = "{}{}{}".format(name, comment, email)
            self.set('gpgkey_uid', uid)

        if self.isempty(o['find']):
            self.set('find', self.get('gpgkey_uid'))

        #
        # set path
        #
        if self.isempty(o['fullpath']):
            fullpath = "{}/{}".format(
                "{}".format(self.get_clean_path(self.get('basepath'))),
                "{}".format(self.get_clean_path(self.get('find')))
            )
            self.set('fullpath', fullpath)

        #
        # set allowed key types
        # rsa1, dsa and ecdsa are explicitly not supported
        #
        allowed     = ["rsa",'ed25519']

        #
        # sanity checks
        #
        if o['gpgkey_type'] not in allowed:
            self.error("invalid gpgkey type specified; recieved [{}] but expected on of {}".format(o['gpgkey_type'], allowed))

        if int(o['gpgkey_bits']) < 4096 and o['gpgkey_type'] == 'rsa':
            self.error("key length below 4096 is not supported for RSA keys; [{}] given".format(o['gpgkey_bits']))

        if int(o['gpgkey_s2k_count']) < 1024 or int(o['gpgkey_s2k_count']) > 65011712:
            self.error("s2k count must be between 1024-65011712; [{}] given".format(o['gpgkey_s2k_count']))

        if int(o['gpgkey_s2k_mode']) != 3:
            self.error("s2k modes other than 3 are currently not supported due to security concerns; [{}] given".format(o['gpgkey_s2k_mode']))

        if o['gpgkey_digest'] not in o['gpgkey_pref']:
            self.error("digest not recognized; [{}] given, but expected on of {}".format(o['gpgkey_digest'], o['gpgkey_pref']))

        if o['gpgkey_s2k_cipher'] not in o['gpgkey_pref']:
            self.error("s2k cipher not recognized; [{}] given, but expected on of {}".format(o['gpgkey_s2k_cipher'], o['gpgkey_pref']))

        if o['gpgkey_s2k_digest'] not in o['gpgkey_pref']:
            self.error("s2k digest not recognized; [{}] given, but expected on of {}".format(o['gpgkey_s2k_digest'], o['gpgkey_pref']))
