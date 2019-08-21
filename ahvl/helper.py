#
# import modules
#
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.utils.display import Display
from distutils.spawn import find_executable
from time import gmtime, strftime
import os
import re

#
# display
#
display = Display()

#
# AhvlBase
#
class AhvlMsg:

    #
    # methods to use ansible's verbose debugging features with a timestamp
    #
    def d(self, prefix, msg):
        return "{}{}{}".format(strftime("%Y-%m-%d %H:%M:%S", gmtime()), prefix, msg)

    def v(self, msg):
        display.v(self.d("  ", msg))

    def vv(self, msg):
        display.vv(self.d("  vv:  ", msg))

    def vvv(self, msg):
        display.vvv(self.d("  vvv:  ", msg))

    def vvvv(self, msg):
        display.vvvv(self.d("  vvvv:  ", msg))

    def debug(self, msg):
        display.debug(self.d("  debug:  ", msg))

    def display(self, msg):
        display.display(msg)

    # fail on validation
    def fail(self, msg, *kargs, **kwargs):

        msg = "\n\nAHVL OPTIONS ERROR:\n{}\n\nOPTIONS:\nkargs: {}\nkwargs: {}".format(msg, kargs, kwargs)
        raise AnsibleError(msg)


msg = AhvlMsg()

#
# AhvlHelper
#
class AhvlHelper:

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

    # function to read the contents of a file
    def get_file_contents(self, file):

        # sanity check
        if not os.path.isfile(file) or not os.access(file, os.R_OK):
            msg.fail("file [{}] does not exist or is not readable; please check the file and try again.".format(file))

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
            msg.fail("could not find a valid fingerprint in string [{}]".format(line))

        # return fingerprint
        return match.group(1)

    # function to extract fingerprint from string
    def extract_bubblebabble(self, line):

        # find bubble babble fingerprint; works for ssh-keygen -B
        regex = r"\d+\s+(\S+)\s{1}.*$"
        match = re.match(regex, line)

        # sanity check
        if re.compile(regex).groups < 1:
            msg.fail("could not find a valid bubble babble fingerprint in string [{}]".format(line))

        # return fingerprint
        return match.group(1)

    # function to create a temporary file
    def write_tmp_file(self, file, contents):

        # sanity check
        if self.isfile(file):
            msg.fail("the tmp file [{}] already exists and we don't intend to overwrite anything")

        # file handler
        f = open(file, "w+")
        f.write(contents)
        f.close()

        # return
        return f

    # function to write password file
    def create_pwd_file(self, file, passphrase):

        msg.vvv("creating password file")

        # write password file
        file    = "{}{}".format(file,'.pwd')
        self.write_tmp_file(file, passphrase)

        # return full path to of password file
        return file
