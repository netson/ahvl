#
# import modules
#
import subprocess
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.utils.display import Display

#
# ansible display
#
display = Display()

#
# process
#
class Process(object):
    
    def __init__(self, proc=None, cmd=[], failonstderr=True, shell=False):

        # set process name and command
        self.setprocess(proc)                  # set process name
        self.setcmd(cmd)                       # set command
        self.failonstderr   = failonstderr     # fail on stderr
        self.stderr         = None
        self.stdout         = None
        self.stderrlines    = []
        self.stdoutlines    = []
        self.shell          = shell

    # function to remove sensitive information from commands
    # by deleting the arguments from a copy of the list
    def __get_safe_args(self):

        # set list for unknown processes
        sensitive = []

        # check for which process the arguments need to be cleaned
        if self.proc == "ssh-keygen":
            sensitive = ["-f", "-N", "-P"]
        if self.proc == "openssl":
            sensitive = ["pass:", "-passin", "-passout"]
        if self.proc == "puttygen":
            sensitive = ["-N"]

        # create a copy of the list to prevent iteration issues when removing items
        safeargs = list(self.cmd)
        for a in self.cmd:
            if a.strip('"').strip("'").startswith(tuple(sensitive)):
                safeargs.remove(a)

        # return safe to print argument list
        return safeargs

    # useless lines removed
    def __clean_stderr(self):

        # remove empty lines
        self.stderrlines = list(filter(None, self.stderrlines))

    # function to fail on stderr messages
    def __fail_on_stderr(self):

        # clean output
        self.__clean_stderr()

        # check if stderr contains any lines
        if len(self.stderrlines) > 0 and self.failonstderr:
            raise AnsibleError("the process generated an error:\n{}".format("\n".join(self.stderrlines)))

    # set stderr and stdout
    def __set_result(self):
        
        # convert stdout and stderr to individual lines
        self.stdoutlines    = self.stdout.rstrip('\n').split("\n")
        self.stderrlines    = self.stderr.rstrip('\n').split("\n")

    # set process to run; accepts known processes only
    def setprocess(self, proc):

        # sanity check
        accepted = ["ssh-keygen", "openssl", "puttygen"]
        if not proc in accepted:
            raise AnsibleError("given process name [{}] is unknown".format(proc))

        # set process and return
        self.proc = proc
        return self

    # set command to run
    def setcmd(self, cmd):
        self.cmd = cmd
        return self

    # determine if process should fail if any stderr messages are generated
    def setfailonstderr(self, fail):
        self.failonstderr = fail

    # return stdout messages
    def getstdout(self):
        return self.stdoutlines

    # return stderr messages
    def getstderr(self):
        return self.stderrlines

    # run the process
    def run(self):

        # output debug info
        if self.shell == True:
            display.vvv("about to run the following subprocess (shell): [{}]".format(self.proc))
            display.vvv("[{}]".format(self.cmd))
        else:
            # remove sensitive arguments before printing debug info
            printable = self.__get_safe_args()
            display.vvv("about to run the following subprocess (sensitive information has been removed): [{}]".format(self.proc))
            display.vvv("[{}]".format(subprocess.list2cmdline(printable)))
            
        # spawn subprocess
        sp = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=self.shell)
        (self.stdout, self.stderr) = sp.communicate();
        rc = sp.returncode # get the exit code

        # check exit/return code
        if rc != 0:
            raise AnsibleError("an error occurred for [{}]; the process exited with code [{}]\n".format(self.proc, rc) +
                               "the process provided the following output: [{}]".format(self.stderr))

        # set result and fail on error
        self.__set_result()
        self.__fail_on_stderr()

        # return the result
        return self
