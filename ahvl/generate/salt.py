#
# import modules
#
from ahvl.options.generatesalt import OptionsGenerateSalt
import random

#
# GenerateSalt
#
class GenerateSalt:

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        #
        # options
        #
        self.opts = OptionsGenerateSalt(variables, lookup_plugin, **kwargs)

    def get_key(self):

        # always include hostname so a unique salt is used on each host, even when using the same password
        return "_".join([self.opts.get('key'),
                         self.opts.hostname.replace(".","_"),
                         self.opts.get('ret'),
                         "salt"])

    def get_length(self):
        
        # return proper length for each hash
        r = self.opts.get('ret')
        if r == "bcrypt":
            return 22
        elif r == "bcryptsha256":
            return 22
        elif r == "sha256crypt":
            return 16
        elif r == "sha512crypt":
            return 16
        elif r == "phpass":
            return 8
        else:
            return 12

    def get_chars(self, chars):

        # set common charsets
        charsets = {"itoa64"   : './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    "alnum"    : '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                   }

        # return
        return charsets[chars]

    def generate(self):

        # get length and characters
        key             = self.get_key() # key name for salt
        length          = self.get_length()
        chars           = self.get_chars(self.opts.get('chars'))

        # generate salt
        rand = random.SystemRandom()
        salt = ''.join([rand.choice(chars) for _ in range(length)])

        # return result as dict
        return salt
