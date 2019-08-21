#
# import modules
#
from ahvl.options.generate.salt import OptionsGenerateSalt
from ahvl.helper import AhvlMsg, AhvlHelper
import random

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# GenerateSalt
#
class GenerateSalt:

    def __init__(self, lookup_plugin):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin
        self.variables      = lookup_plugin.variables
        self.kwargs         = lookup_plugin.kwargs

        # set options
        self.opts = OptionsGenerateSalt(lookup_plugin)


    def get_key(self):

        # always include hostname so a unique salt is used on each host, even when using the same password
        return "_".join([self.opts.get('in'),
                         self.opts.get('hostname').replace(".","_"),
                         self.opts.get('out'),
                         "salt"])


    def get_length(self):
        
        # return proper length for each hash
        r = self.opts.get('out')
        if r == "argon2":
            return 22
        elif r == "grubpbkdf2sha512":
            return 64
        elif r == "pbkdf2sha512":
            return 64
        elif r == "pbkdf2sha256":
            return 32
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
        chars           = self.get_chars(self.opts.get('salt_chars'))

        # generate salt
        rand = random.SystemRandom()
        salt = ''.join([rand.choice(chars) for _ in range(length)])

        # return result as dict
        return salt
