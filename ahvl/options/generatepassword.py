#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGeneratePassword
#
class OptionsGeneratePassword(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_generate_password"

    def required(self):

        # return list of required options
        return [
            'type',
            'entropy',
        ]

    def defaults(self):

        # set default option values
        options = {
            'type'      : 'word',        # type of password to generate; word or phrase
            'entropy'   : 'secure',      # strength of password; check passlib docs for allowed values
            'length'    : 32,            # length of password; if omitted is auto calculated based on entropy
            'chars'     : None,          # specific string of characters to use when generating passwords
            'charset'   : 'ascii_72',    # specific charset to use when generating passwords
            'words'     : None,          # list of words to use when generating passphrase
            'wordset'   : 'eff_long',    # predefined list of words to use when generating passphrase; check passlib docs for allowed values
            'sep'       : ' ',           # word separator for passphrase
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # sanity checks
        #
        if o['type'] == 'word' and self.isempty(o['charset']):
            self.error("generating password of type [{}] requires the [charset] option to be set".format(o['type']))

        if o['type'] == 'phrase' and self.isempty(o['wordset']):
            self.error("generating password of type [{}] requires the [wordset] option to be set".format(o['type']))
