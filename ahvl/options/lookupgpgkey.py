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
        ]

    def defaults(self):

        # set default option values
        options = {
            'basepath'          : "gpgkeys",                    # basepath
            'gpgkey_fullname'   : None,                         # full name for key
            'gpgkey_email'      : None,                         # email for key
            'gpgkey_comment'    : None,                         # comment for key
            'gpgkey_uid'        : None,                         # uid for key
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

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
        # set accepted values
        #
        allowed_in  = ["master_private",
                       "master_private_armored",
                       "master_keyid",
                       "master_fingerprint",
                       "master_expirationdate",
                       "master_keytype",
                       "master_keybits",
                       "master_keycurve",
                       "master_password",
                      ]

        #
        # sanity checks
        #
        if o['in'] not in allowed_in:
            self.error("value for [in] parameter is invalid; [{}] given, but expected one of {}".format(o['in'], allowed_in))

        if (self.isempty(o['basepath']) and self.isempty(o['gpgkey_udi'])) or self.isempty(o['fullpath']):
            self.error("either provide a basepath and gpgkey_uid, or provide the fullpath directly");
