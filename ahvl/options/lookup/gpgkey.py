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
            'gpgkey_keyset'     : 'regular',                    # keyset to generate
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
        allowed_keyset = ['regular', 'backup']

        allowed_regular = [
            'master_cert_pub_key_armored',
            'master_cert_sec_key_armored',
            'master_cert_sec_keytype',
            'master_cert_sec_keyuid',
            'master_cert_sec_password',
            'master_cert_sec_fingerprint',
            'master_cert_sec_keycurve',
            'master_cert_sec_keygrip',
            'master_cert_sec_keybits',
            'master_cert_sec_creationdate',
            'master_cert_sec_keyid',
            'master_cert_sec_expirationdate',
            'subkey_sign_sec_key_armored',
            'subkey_sign_sec_fingerprint',
            'subkey_sign_sec_keycurve',
            'subkey_sign_sec_keygrip',
            'subkey_sign_sec_keybits',
            'subkey_sign_sec_creationdate',
            'subkey_sign_sec_keyid',
            'subkey_sign_sec_expirationdate',
            'subkey_encr_sec_key_armored',
            'subkey_encr_sec_fingerprint',
            'subkey_encr_sec_keycurve',
            'subkey_encr_sec_keygrip',
            'subkey_encr_sec_keybits',
            'subkey_encr_sec_creationdate',
            'subkey_encr_sec_keyid',
            'subkey_encr_sec_expirationdate',
            'subkey_auth_sec_key_armored',
            'subkey_auth_sec_fingerprint',
            'subkey_auth_sec_keycurve',
            'subkey_auth_sec_keygrip',
            'subkey_auth_sec_keybits',
            'subkey_auth_sec_creationdate',
            'subkey_auth_sec_keyid',
            'subkey_auth_sec_expirationdate',
        ]

        allowed_backup = [
            'sign_master_cert_pub_key_armored',
            'sign_master_cert_sec_key_armored',
            'sign_master_cert_sec_keytype',
            'sign_master_cert_sec_keyuid',
            'sign_master_cert_sec_password',
            'sign_master_cert_sec_fingerprint',
            'sign_master_cert_sec_keycurve',
            'sign_master_cert_sec_keygrip',
            'sign_master_cert_sec_keybits',
            'sign_master_cert_sec_creationdate',
            'sign_master_cert_sec_keyid',
            'sign_master_cert_sec_expirationdate',
            'sign_subkey_sign_sec_key_armored',
            'sign_subkey_sign_sec_fingerprint',
            'sign_subkey_sign_sec_keycurve',
            'sign_subkey_sign_sec_keygrip',
            'sign_subkey_sign_sec_keybits',
            'sign_subkey_sign_sec_creationdate',
            'sign_subkey_sign_sec_keyid',
            'sign_subkey_sign_sec_expirationdate',
            'encr_master_cert_pub_key_armored',
            'encr_master_cert_sec_key_armored',
            'encr_master_cert_sec_keytype',
            'encr_master_cert_sec_keyuid',
            'encr_master_cert_sec_password',
            'encr_master_cert_sec_fingerprint',
            'encr_master_cert_sec_keycurve',
            'encr_master_cert_sec_keygrip',
            'encr_master_cert_sec_keybits',
            'encr_master_cert_sec_creationdate',
            'encr_master_cert_sec_keyid',
            'encr_master_cert_sec_expirationdate',
            'encr_subkey_encr_sec_key_armored',
            'encr_subkey_encr_sec_fingerprint',
            'encr_subkey_encr_sec_keycurve',
            'encr_subkey_encr_sec_keygrip',
            'encr_subkey_encr_sec_keybits',
            'encr_subkey_encr_sec_creationdate',
            'encr_subkey_encr_sec_keyid',
            'encr_subkey_encr_sec_expirationdate',
        ]

        #
        # sanity checks
        #
        if o['gpgkey_keyset'] not in allowed_keyset:
            msg.fail("value for [gpgkey_keyset] parameter is invalid; [{}] given, but expected one of {}".format(o['gpgkey_keyset'], allowed_keyset))

        if o['gpgkey_keyset'] == 'regular' and o['in'] not in allowed_regular:
            msg.fail("value for [in] parameter is invalid for keyset [{}]; [{}] given, but expected one of {}".format(o['gpgkey_keyset'], o['in'], allowed_regular))

        if o['gpgkey_keyset'] == 'backup' and o['in'] not in allowed_backup:
            msg.fail("value for [in] parameter is invalid for keyset [{}]; [{}] given, but expected one of {}".format(o['gpgkey_keyset'], o['in'], allowed_backup))

        if hlp.isempty(o['path']):
            msg.fail("path is missing");
