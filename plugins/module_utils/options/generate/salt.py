#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsGenerateSalt
#
class OptionsGenerateSalt(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_generate_salt"


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
            'salt_chars' : 'itoa64',     # salt charset
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
        return ['salt_chars',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # check allowed salt chars
        #
        allowed = ['itoa64', 'alnum']

        if o['salt_chars'] not in allowed:
            msg.fail("option [salt_chars] invalid; [{}] given, but expected one of {}".format(o['salt_chars'], allowed))
