#
# import modules
#
from ahvl.helper import AhvlMsg, AhvlHelper
from passlib import pwd
import shutil
import os

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# OptionsBase
#
class OptionsBase:

    def __init__(self, lookup_plugin):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin

        # set everyting
        self.set_prefix()
        self.set_defaults()
        self.set_options()
        self.set_appended()
        self.set_path()

        # validate options
        self.validate_all()

    # progress indicator
    def pi(self, m):

        # set progress
        msg.vvvv("at [{}] within [{}]".format(m, self.__class__.__name__))


    # set prefix
    # prefix is used to prevent polluting the ansible variable global scope
    # each option class has its own prefix, but all start with ahvl_
    def set_prefix(self):

        self.pi("set_prefix")

        # set option prefix
        self.prefix = self.get_prefix()


    # set option defaults
    def set_defaults(self):

        self.pi("set_defaults")

        # main/general options
        self.options = {
            'hostname'      : self.lookup_plugin.variables['inventory_hostname'] if 'inventory_hostname' in self.lookup_plugin.variables else None,
            'ahvl_tmppath'  : None,
            'find'          : None,
            'in'            : None,
            'out'           : 'hexsha512',
            'path'          : None,
            'autogenerate'  : True,
            'renew'         : False,
        }

        # get and merge default options
        self.options = self.merge(self.options, self.get_defaults())


    # set options
    def set_options(self):

        self.pi("set_options")

        # set options
        for opt in self.options.keys():

            self.pi("option {}".format(opt))

            # set option name as it can be found in the variables dict
            # also make it uppercase when environment variables are used
            varopt = "{}_{}".format(self.prefix, opt)
            varopt_upper = varopt.upper()

            # check if options have been set as function arguments
            if opt in self.lookup_plugin.kwargs.keys() and self.lookup_plugin.kwargs[opt] is not None:
                self.set(opt, self.lookup_plugin.kwargs[opt])

            # check if options have been set as environment variable
            elif varopt_upper in os.environ and os.environ[varopt_upper] is not None:
                self.set(opt, os.environ[varopt_upper])

            # check if options have been set as playbook variables
            elif varopt in self.lookup_plugin.variables and self.lookup_plugin.variables[varopt] is not None:
                self.set(opt, self.lookup_plugin.variables[varopt])

            # check if options have been set as nested playbook variables
            elif self.prefix in self.lookup_plugin.variables and self.lookup_plugin.variables[self.prefix] is not None and opt in self.lookup_plugin.variables[self.prefix]:
                self.set(opt, self.lookup_plugin.variables[self.prefix][opt])

            # check if connection options have been set using ansible-doc
            # this 'prefix' is different than the self.prefix, as this is about the option name itself regardless of prefix
            elif self.lookup_plugin is not None and opt.startswith("ahvl_"):
                lkpopt = self.lookup_plugin.get_option(opt)
                if lkpopt is not None:
                    self.set(opt, lkpopt)


    # set appended
    def set_appended(self):

        self.pi("set_appended")

        # get and merge appended options
        self.options = self.merge(self.options, self.get_appended())


    # set path
    def set_path(self):

        self.pi("set_path")

        # set path if not done so yet
        if self.options['path'] is not None:
            path = self.options['path']
        else:
            path = self.get_path()

        # replace path variables
        if path is not None:

            # set possible variables
            pathvars = {
                '{find}'        : self.get('find'),
                '{hostname}'    : self.get('hostname'),
            }

            # replace variables in path
            for p,v in pathvars.items():
                if v is not None:
                    path = path.replace(p, self.get_clean_path(v))

        else:
            path = ''

        # set path
        self.set('path', self.get_clean_path(path))


    # validate all
    def validate_all(self):

        self.pi("validate_tmpdir")

        # check if tempdir exists and is writeable
        if hlp.isempty(self.get('ahvl_tmppath')) or not hlp.isdir(self.get('ahvl_tmppath')) or not hlp.iswriteabledir(self.get('ahvl_tmppath')):
            msg.fail("the temp dir [{}] either does not exist or is not writeable".format(self.get('ahvl_tmppath')), **self.options)
            exit()

        # check required fields
        self.pi("validate_required")
        reqs = self.get_required_options()
        for opt in reqs:
            if opt not in self.options or hlp.isempty(self.get(opt)):
                msg.fail("option [{}] is required and is empty [{}]".format(opt, self.__class__.__name__), **self.options)

        # check for valid out value
        self.pi("validate_out")
        allowed_out = ["plaintext", "hexsha256", "hexsha512", "sha256crypt", "sha512crypt", "grubpbkdf2sha512",
                       "phpass", "mysql41", "postgresmd5", "pbkdf2sha256", "pbkdf2sha512", "argon2"]

        if 'out' in self.options.keys() and self.options['out'] not in allowed_out:
            msg.fail("option out has value [{}]; expected one of {}".format(self.options['out'], allowed_out), **self.options)

        # validate any option class specific items
        self.pi("validate_other")
        self.validate()


    # required fields for lookups
    def get_required_options(self):

        # lookup classes always have the following additional required options
        lookup_req = ['find', 'in', 'out', 'path']

        # return the proper list of required fields
        if self.__class__.__name__.startswith('OptionsLookup'):
            return self.get_required() + lookup_req
        else:
            return self.get_required()


    # get option
    def get(self, opt):

        # sanity check
        if opt not in self.options.keys():
            msg.fail("the requested option [{}] does not exist [{}]".format(opt, self.__class__.__name__), **self.options)

        # return value
        return self.options[opt]


    # set option
    def set(self, opt, val):

        # sanity check
        if opt not in self.options.keys():
            msg.fail("the option you are trying to set [{}] is invalid".format(opt), self.options)

        # set option
        self.options[opt] = val

        # return value
        return self.options[opt]


    # function to get clean, safe path
    def get_clean_path(self, path):

        # sanity check
        if path is None:
            return path

        # define characters to be removed
        rem = ['(',')','<','>','[',']']
        for r in rem: path = path.replace(r, "")

        rep = ['.',' ']
        for r in rep: path = path.replace(r, "_")

        sub = ['@']
        for r in sub: path = path.replace(r, "_at_")

        # strip leading and trailing slashes
        path = path.strip("/")

        return path

    # function to get temp path
    def get_tmp_dir(self):
        return "{}/".format(self.get('ahvl_tmppath'))

    # function to get temp filename
    def get_tmp_filename(self, with_dir=True):
        filename = pwd.genword(entropy="secure", charset="ascii_50", length=10)
        if with_dir:
            return "{}{}".format(self.get_tmp_dir(), filename)
        else:
            return filename

    # function to delete temporary directory
    def delete_tmp_dir(self):

        # shorthand
        tmpdir = self.get_tmp_dir().rstrip("/")

        # sanity check
        donotdelete = ["/","/bin","/boot","/cdrom","/dev",
                       "/etc","/home","/lib","/lib64","/lost",
                       "/media","/mnt","/opt","/proc","/root",
                       "/run","/sbin","/snap","/srv","/sys",
                       "/timeshift","/tmp","/usr","/var",
                      ]

        if tmpdir in donotdelete:
            msg.fail("oops; it seems like you are trying to delete a sytem directory? that seems wrong [{}]".format(tmpdir))

        # remove dir
        if hlp.isdir(self.get_tmp_dir()) and tmpdir not in donotdelete:
            msg.vv("deleting temporary directory and everything in it [{}]".format(tmpdir))
            shutil.rmtree(tmpdir)


    # function to merge two dictionaries
    # the values of y will overwrite those of x
    def merge(self, x, y):
        z = x.copy()
        z.update(y)
        return z

    # return all options
    def getall(self):
        return self.options
