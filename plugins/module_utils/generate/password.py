#
# import modules
#
from ahvl.options.generate.password import OptionsGeneratePassword
from ahvl.helper import AhvlMsg, AhvlHelper
from passlib import pwd

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# GeneratePassword
#
class GeneratePassword:

    def __init__(self, lookup_plugin):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin
        self.variables      = lookup_plugin.variables
        self.kwargs         = lookup_plugin.kwargs

        # set options
        self.opts = OptionsGeneratePassword(lookup_plugin)


    def generate(self):

        # password or passphrase
        if self.opts.get('pwd_type') == "phrase":
            passwd = pwd.genphrase(entropy=self.opts.get('pwd_entropy'),
                                   length=self.opts.get('pwd_length'),
                                   returns=None,
                                   words=self.opts.get('pwd_words'),
                                   wordset=self.opts.get('pwd_wordset'),
                                   sep=self.opts.get('pwd_sep'))
        else:
            passwd = pwd.genword(entropy=self.opts.get('pwd_entropy'),
                                   length=self.opts.get('pwd_length'),
                                   returns=None,
                                   chars=self.opts.get('pwd_words'),
                                   charset=self.opts.get('pwd_charset'))

        # return result
        return passwd
