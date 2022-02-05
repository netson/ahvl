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
# OptionsGenerateGPGKey
#
class OptionsGenerateGPGKey(OptionsBase):


    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_generate_gpgkey"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return None


    # set default options
    def get_defaults(self):

        # set default option values
        return {
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
            'gpgkey_comment'        : None,                     # concatenated into a uid like; fullname (comment) <email>
            'gpgkey_uid'            : None,                     # the uid
            'gpgkey_expirationdate' : '0',                      # key expiration date in the format of [YYYY-MM-DD], [YYYYMMDDThhmmss], seconds=(int)|(int)[d|w|m|y]|0
            'gpgkey_bits'           : '4096',                   # key length; only used by RSA keys; will be added to the gpgkey_algo variable for RSA keys
            'gpgkey_type'           : 'ed25519',                # main key type to use for all 4 keys (master + 3 subkeys); supported are rsa|ed25519
            'gpgkey_bin'            : None,                     # full path to gpg binary
            'gpgkey_keyset'         : 'regular',                # set of keys to generate; regular or backup (i.e. for duplicity)
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        gpgkey_conf	= o['gpgkey_conf']
        gpgkey_uid  = o['gpgkey_uid']
        gpgkey_bin  = o['gpgkey_bin']
        gpgkey_comm = o['gpgkey_comment']

		# set pref
        gpgkey_conf.append("default-preference-list {}".format(" ".join(o['gpgkey_pref'])))

        #
        # set find/uid/path
        # if path is given, use path
        # else, if find is given, use find
        # else, if uid is given, use uid
        # else, construct uid based on fullname, email and comment
        #
        if hlp.isempty(gpgkey_uid):
            # determine uid
            name        = "{}".format(o['gpgkey_fullname'])
            email       = " <{}>".format(o['gpgkey_email'])
            comment     = " ({})".format(o['gpgkey_comment']) if not hlp.isempty(o['gpgkey_comment']) else ""
            gpgkey_uid  = "{}{}{}".format(name, comment, email)

        # determine gpg2 binary
        if hlp.isempty(gpgkey_bin):
            gpgkey_bin  = hlp.find_binary('gpg2')

        # determine comment
        if hlp.isempty(gpgkey_comm):
            gpgkey_comm = o['hostname']

        # return list of overide options or calculated options
        return {
            'gpgkey_conf'   : gpgkey_conf,
            'gpgkey_uid'    : gpgkey_uid,
            'gpgkey_bin'    : gpgkey_bin,
            'gpgkey_comment': gpgkey_comm,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['gpgkey_uid',
                'gpgkey_bin',
                'gpgkey_conf',
                'gpgkey_pref',
                'gpgkey_digest',
                'gpgkey_s2k_cipher',
                'gpgkey_s2k_digest',
                'gpgkey_s2k_mode',
                'gpgkey_s2k_count',
                'gpgkey_expirationdate',
                'gpgkey_type',
                'gpgkey_keyset',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set allowed key types
        # rsa1, dsa and ecdsa are explicitly not supported
        #
        allowed     = ["rsa",'ed25519']

        #
        # sanity checks
        #
        if o['gpgkey_type'] not in allowed:
            msg.fail("invalid gpgkey type specified; recieved [{}] but expected on of {}".format(o['gpgkey_type'], allowed))

        if int(o['gpgkey_bits']) < 4096 and o['gpgkey_type'] == 'rsa':
            msg.fail("key length below 4096 is not supported for RSA keys; [{}] given".format(o['gpgkey_bits']))

        if int(o['gpgkey_s2k_count']) < 1024 or int(o['gpgkey_s2k_count']) > 65011712:
            msg.fail("s2k count must be between 1024-65011712; [{}] given".format(o['gpgkey_s2k_count']))

        if int(o['gpgkey_s2k_mode']) != 3:
            msg.fail("s2k modes other than 3 are currently not supported due to security concerns; [{}] given".format(o['gpgkey_s2k_mode']))

        if o['gpgkey_digest'] not in o['gpgkey_pref']:
            msg.fail("digest not recognized; [{}] given, but expected on of {}".format(o['gpgkey_digest'], o['gpgkey_pref']))

        if o['gpgkey_s2k_cipher'] not in o['gpgkey_pref']:
            msg.fail("s2k cipher not recognized; [{}] given, but expected on of {}".format(o['gpgkey_s2k_cipher'], o['gpgkey_pref']))

        if o['gpgkey_s2k_digest'] not in o['gpgkey_pref']:
            msg.fail("s2k digest not recognized; [{}] given, but expected on of {}".format(o['gpgkey_s2k_digest'], o['gpgkey_pref']))

        if not hlp.isexpirationdate(o['gpgkey_expirationdate']):
            msg.fail("expiration date [{}] not recognized; please provide one of the following formats: YYYY-DD-MM or <int>[d|w|m|y] or 0 (doesn't expire)")
