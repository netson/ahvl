#
# import modules
#
from ahvl.options.base import OptionsBase

#
# OptionsLookupPassword
#
class OptionsLookupPassword(OptionsBase):

    def prefix(self):
        self.prefix = "ahvl_password"

    def required(self):

        # return list of required options
        return [
            'key',
            'ret',
        ]

    def defaults(self):

        # set default option values
        options = {
            'basepath'  : "hosts/{}".format(self.hostname), # basepath
            'path'      : None,                             # path to find secret
            'fullpath'  : None,                             # path to find secret; set in validate()
            'key'       : None,                             # key of secret
            'ret'       : None,                             # return hash/plain
            'renew'     : False,                            # force generating a new password regardless if it exists or not
                                                            # be careful with this setting, as it will renew on each iteration
        }

        # return
        return options

    def validate(self):

        # write shorthand
        o = self.options

        #
        # set path
        #
        if self.isempty(o['fullpath']):
            fullpath = "{}/{}".format(
                "{}".format(o['basepath']).strip("/"),
                "{}".format(o['path']).strip("/")
            )
            self.set('fullpath', fullpath)

        #
        # set accepted values
        #
        allowed_ret = ["plaintext", "hexsha256", "hexsha512", "sha256crypt",
                       "sha512crypt", "phpass", "mysql41", "postgresmd5", "onetime"]

        #
        # sanity checks
        #
        if o['ret'] not in allowed_ret:
            self.error("value for ret parameter is invalid; [{}] given, but expected one of {}".format(o['ret'], allowed_ret))

        if (self.isempty(o['basepath']) and self.isempty(o['path'])) or self.isempty(o['fullpath']):
            self.error("either provide a basepath and path, or provide the fullpath directly");
