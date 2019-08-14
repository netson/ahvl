#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGenerateSalt
#
class OptionsGenerateSalt(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_generate_salt"

    def required(self):

        # return list of required options
        return [
            'key',
            'ret',
            'chars',
        ]

    def defaults(self):

        # set default option values
        options = {
            'key'   : None,         # lookup key
            'ret'   : None,         # return method; used to generate unique salt for each
            'chars' : 'itoa64',     # salt charset
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options
