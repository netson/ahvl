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
# OptionsLookupGPGKey
#
class OptionsLookupGPGKey(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_gpgkey"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return "gpgkeys/{find}"


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {
            'gpgkey_fullname'   : None,                         # full name for key
            'gpgkey_email'      : None,                         # email for key
            'gpgkey_comment'    : None,                         # comment for key
            'gpgkey_uid'        : None,                         # uid for key
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        gpgkey_uid  = o['gpgkey_uid']
        find        = o['find']

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

        if hlp.isempty(find):
            find        = self.get_clean_path(gpgkey_uid)

        # return list of overide options or calculated options
        return {
            'gpgkey_uid'    : gpgkey_uid,
            'find'          : find,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['gpgkey_fullname',
                'gpgkey_email',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set accepted values
        #
        allowed_in  = ["master_sec_key_armored",        # from stdout
                       "master_sec_keyid",              # from info
                       "master_sec_keygrip",            # from info
                       "master_sec_fingerprint",        # from info
                       "master_sec_creationdate",       # from info
                       "master_sec_expirationdate",     # from info
                       "master_sec_keybits",            # from info
                       "master_sec_keycurve",           # from info
                       "master_sec_keytype",            # from opts
                       "master_sec_keyuid",             # from opts
                       "master_sec_password",           # from opts
                      ]

        #
        # sanity checks
        #
        if o['in'] not in allowed_in:
            msg.fail("value for [in] parameter is invalid; [{}] given, but expected one of {}".format(o['in'], allowed_in))

        if hlp.isempty(o['path']):
            msg.fail("path is missing");
