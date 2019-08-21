#
# import modules
#
from ahvl.options.base import OptionsBase
from ahvl.helper import AhvlMsg, AhvlHelper
import os

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# OptionsLookupCredential
#
class OptionsLookupCredential(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_credential"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return "credentials/{find}"


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {}


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # return list of overide options or calculated options
        return {}


    # set required options
    def get_required(self):

        # return required options - list
        return []


    def validate(self):

        # set shorthand
        o = self.options

        #
        # sanity checks
        #
        if hlp.isempty(o['path']):
            msg.fail("path is missing");
