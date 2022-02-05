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
# OptionsLookupPassword
#
class OptionsLookupPassword(OptionsBase):

    # set option prefix
    def get_prefix(self):

        # return option prefix
        return "ahvl_password"


    # set path
    # useable variables:
    # - {find}
    # - {hostname}
    def get_path(self):

        # return basepath
        return "hosts/{hostname}/{find}"


    # set default options
    def get_defaults(self):

        # set default option values - dict
        return {}


    # calculate any remaining options
    def get_appended(self):

        # set shorthand
        o = self.options

        # set options to append
        find        = o['find']

        # if find is empty, determine the value via the basename of the path
        if hlp.isempty(find) and not hlp.isempty(o['path']):
            # determine uid
            find    = os.path.basename(o['path'])

        # return list of overide options or calculated options
        return {
            'find'          : find,
        }


    # set required options
    def get_required(self):

        # return required options - list
        return ['in',
                'out',
               ]


    def validate(self):

        # set shorthand
        o = self.options

        #
        # sanity checks
        #
        if hlp.isempty(o['path']):
            msg.fail("path is missing");
