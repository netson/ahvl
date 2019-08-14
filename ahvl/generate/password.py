#
# import modules
#
from ahvl.options.generatepassword import OptionsGeneratePassword
from passlib import pwd

#
# GeneratePassword
#
class GeneratePassword:

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        #
        # options
        #
        self.opts = OptionsGeneratePassword(variables, lookup_plugin, **kwargs)

    def generate(self):

        # password or passphrase
        if self.opts.get('type') == "phrase":
            passwd = pwd.genphrase(entropy=self.opts.get('entropy'),
                                   length=self.opts.get('length'),
                                   returns=None,
                                   words=self.opts.get('words'),
                                   wordset=self.opts.get('wordset'),
                                   sep=self.opts.get('sep'))
        else:
            passwd = pwd.genword(entropy=self.opts.get('entropy'),
                                   length=self.opts.get('length'),
                                   returns=None,
                                   chars=self.opts.get('words'),
                                   charset=self.opts.get('charset'))

        # return result
        return passwd
