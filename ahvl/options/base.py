#
# import modules
#
import os
import re
from distutils.spawn import find_executable
from passlib import pwd
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.utils.display import Display

#
# ansible display
#
display = Display()

#
# OptionsBase
#
class OptionsBase():

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        # set hostname
        self.hostname       = None
        if 'inventory_hostname' in variables:
            self.hostname   = variables['inventory_hostname']

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin

        # set dicts
        self.options        = self.defaults()   # options
        self.reqs           = self.required()   # required options

        # init and validate
        display.vvvv("loading options object [{}]".format(self.__class__.__name__))
        self.prefix()
        self.initialize(variables, **kwargs)
        self.validate()
        self.check_required()

    # get option
    def get(self, opt):

        # sanity check
        if opt not in self.options.keys():
            raise AnsibleError("the requested option [{}] does not exist [{}]".format(opt, self.__class__.__name__))

        # return value
        return self.options[opt]

    # set option
    def set(self, opt, val):

        # sanity check
        if opt not in self.options.keys():
            raise AnsibleError("the option you are trying to set [{}] is invalid".format(opt))

        # set option
        self.options[opt] = val

        # return value
        return self.options[opt]

    # empty function to set defaults
    def defaults(self):
        pass

    # set prefix; done from child class
    def prefix(self):
        pass

    # merge given options with ansible variables
    def initialize(self, variables, **kwargs):

        display.vvvv("initializing options object [{}]".format(self.__class__.__name__))

        # always add tmppath/find/in/out/basepath/fullpath/renew to options
        if 'ahvl_tmppath' not in self.options:
            self.options['ahvl_tmppath'] = None

        if 'find' not in self.options:
            self.options['find'] = None

        if 'in' not in self.options:
            self.options['in'] = None

        if 'out' not in self.options:
            self.options['out'] = 'hexsha512'

        if 'basepath' not in self.options:
            self.options['basepath'] = None

        if 'fullpath' not in self.options:
            self.options['fullpath'] = None

        if 'renew' not in self.options:
            self.options['renew'] = False

        for opt in self.options.keys():
            # set option name as it can be found in the variables dict
            # also make it uppercase when environment variables are used
            varopt = "{}_{}".format(self.prefix, opt)
            varopt_upper = varopt.upper()

            # check if options have been set as function arguments
            if opt in kwargs.keys() and kwargs[opt] is not None:
                self.set(opt, kwargs[opt])

            # check if options have been set as environment variable
            elif varopt_upper in os.environ and os.environ[varopt_upper] is not None:
                self.set(opt, os.environ[varopt_upper])

            # check if options have been set as playbook variables
            elif varopt in variables and variables[varopt] is not None:
                self.set(opt, variables[varopt])

            # check if options have been set as nested playbook variables
            elif self.prefix in variables and variables[self.prefix] is not None and opt in variables[self.prefix]:
                self.set(opt, variables[self.prefix][opt])

            # check if connection options have been set using ansible-doc
            elif self.lookup_plugin is not None and opt.startswith("ahvl_"):
                lkpopt = self.lookup_plugin.get_option(opt)
                if lkpopt is not None:
                    self.set(opt, lkpopt)

        # check if tempdir exists and is writeable
        if self.isempty(self.get('ahvl_tmppath')) or not self.isdir(self.get('ahvl_tmppath')) or not self.iswriteabledir(self.get('ahvl_tmppath')):
            self.error("the temp dir [{}] either does not exist or is not writeable".format(self.get('ahvl_tmppath')))

    #
    # check required options
    #
    def check_required(self):

        display.vvvv("checking required field for options object [{}]".format(self.__class__.__name__))

        for opt,val in self.options.items():
            if opt in self.reqs and self.isempty(val):
                self.error("option [{}] is required and is empty [{}]".format(opt, self.__class__.__name__))

        # check for valid find/in/out values, only when these options are for LookupOptions
        if self.__class__.__name__.startswith('OptionsLookup'):
            if 'find' not in self.options.keys() or self.isempty(self.options['find']):
                self.error("option [find] is required and is empty [{}]".format(self.__class__.__name__))

            if 'in' not in self.options.keys() or self.isempty(self.options['in']):
                self.error("option [in] is required and is empty [{}]".format(self.__class__.__name__))

            if 'out' not in self.options.keys() or self.isempty(self.options['out']):
                self.error("option [out] is required and is empty [{}]".format(self.__class__.__name__))

        # check for valid out value
        allowed_out = ["plaintext", "hexsha256", "hexsha512", "sha256crypt",
                       "sha512crypt", "phpass", "mysql41", "postgresmd5", "onetime"]

        if 'out' in self.options.keys() and self.options['out'] not in allowed_out:
            self.error("option out has value [{}]; expected one of {}".format(self.options['out'], allowed_out))

    # empty function to validate options
    def validate(self):
        pass

    # helper method to check if value is empty or None
    def isempty(self, v):

        # check if value is empty
        if v is None or v == '':
            return True
        else:
            return False

    # function to check if directory exists
    def isdir(self, path):
        return os.path.isdir(path)

    # function to check if directory is writeable
    def iswriteabledir(self, path):
        return os.access(path, os.W_OK)

    # function to check if file exists
    def isfile(self, file):
        return os.path.isfile(file)

    # function to check if file is executable
    def isexecutablefile(self, file):
        return os.access(file, os.X_OK)

    # function to check if file is readable
    def isreadablefile(self, file):
        return os.access(file, os.R_OK)

    # function to check if file is writeable
    def iswriteablefile(self, file):
        return os.access(file, os.W_OK)

    # function to check valid expiration date
    def isexpirationdate(self, exp):

        # allow 0
        if int(exp) == 0:
            return True

        # set regexes to validate input
        regex1 = '^\d{4}-\d\d-\d\d$'    # ISO date format YYYY-DD-MM
        regex2 = '^\d+[d|w|m|y]$'       # <int>[d|w|m|y]
        match1 = re.compile(regex1).match
        match2 = re.compile(regex2).match

        # test regexes
        try:            
            if match1(exp) is not None or match2(exp) is not None:
                return True
        except:
            pass
        return False

    # function to find default binaries in system path
    def find_binary(self, binary):
        return find_executable(binary)

    # function to get clean, safe path
    def get_clean_path(self, path):

        # sanity check
        if path is None:
            return path

        # define characters to be replaced
        rep = ['.',' ','(',')','<','>','@']
        for r in rep:
            path.replace(r, "_")

        # strip leading and trailing slashes
        path.strip("/")

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

    # function to delete temporary files
    def delete_tmp_files(self, tempfile, filenames):

        # remove any temporary files
        for f,p in filenames.items():
            tmpfile = p.format(tempfile)
            if os.path.isfile(tmpfile):
                os.remove(tmpfile)

    # function to delete temporary directory
    def delete_tmp_dir(self, tmpdir):

        # remove dir
        if self.isdir(tmpdir):
            os.rmdir(tmpdir)

    # function to merge two dictionaries
    def merge(self, x, y):
        z = x.copy()
        z.update(y)
        return z

    # function to read the contents of a file
    def get_file_contents(self, file):

        # sanity check
        if not os.path.isfile(file) or not os.access(file, os.R_OK):
            self.error("file [{}] does not exist or is not readable; please check the file and try again.".format(file))

        # read file and return contents
        with open(file, 'r') as content_file:
            return content_file.read()

    # function to extract fingerprint from string
    def extract_fingerprint(self, line):

        # find fingerprint; works for ssh-keygen md5 and sha256 types
        regex = r"[^:]+:(\S+)\s{1}.*$"
        match = re.match(regex, line)

        # sanity check
        if re.compile(regex).groups < 1:
            self.error("could not find a valid fingerprint in string [{}]".format(line))

        # return fingerprint
        return match.group(1)

    # function to extract fingerprint from string
    def extract_bubblebabble(self, line):

        # find bubble babble fingerprint; works for ssh-keygen -B
        regex = r"\d+\s+(\S+)\s{1}.*$"
        match = re.match(regex, line)

        # sanity check
        if re.compile(regex).groups < 1:
            self.error("could not find a valid bubble babble fingerprint in string [{}]".format(line))

        # return fingerprint
        return match.group(1)

    # return all options
    def getall(self):
        return self.options

    # fail on validation
    def error(self, msg):
        msg = "\n\nHASHI_VAULT OPTIONS ERROR:\n{}\n\nOPTIONS:\n{}".format(msg, self.options)
        raise AnsibleError(msg)
