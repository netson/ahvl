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
# OptionsGeneratePassword
#
class OptionsGeneratePassword(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_generate_password"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):
        return None


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {
            'pwd_type'      : 'word',        # type of password to generate; word or phrase
            'pwd_entropy'   : 'secure',      # strength of password; check passlib docs for allowed values
            'pwd_length'    : 32,            # length of password; if omitted is auto calculated based on entropy
            'pwd_chars'     : None,          # specific string of characters to use when generating passwords
            'pwd_charset'   : 'ascii_72',    # specific charset to use when generating passwords
            'pwd_words'     : None,          # list of words to use when generating passphrase
            'pwd_wordset'   : 'eff_long',    # predefined list of words to use when generating passphrase; check passlib docs for allowed values
            'pwd_sep'       : ' ',           # word separator for passphrase
        }


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # return list of overide options or calculated options
        return {}


    # set required options
    def get_required(self):

        # return required options - list
        return ['pwd_type',
                'pwd_entropy',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # set accepted values
        #
        allowed_type = ["word", "phrase"]

        #
        # sanity checks
        #
        # write shorthand
        o = self.options

        #
        # sanity checks
        #
        if o['pwd_type'] not in allowed_type:
            msg.fail("value for password type is invalid; [{}] given but expected one of {}".format(o['pwd_type'], allowed_type))

        if o['pwd_entropy'] != 'secure':
            msg.fail("option [pwd_entropy] should be set to secure")

        if o['pwd_type'] == 'word' and hlp.isempty(o['pwd_charset']):
            msg.fail("generating password of type [{}] requires the [pwd_charset] option to be set".format(o['pwd_type']))

        if o['pwd_type'] == 'phrase' and hlp.isempty(o['pwd_wordset']):
            msg.fail("generating password of type [{}] requires the [pwd_wordset] option to be set".format(o['pwd_type']))
