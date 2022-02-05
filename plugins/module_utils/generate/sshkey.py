#
# import modules
#
from ahvl.options.generate.sshkey import OptionsGenerateSSHKey
from ahvl.helper import AhvlMsg, AhvlHelper
from ahvl.process import Process
from packaging import version
import re

#
# helper/message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# GenerateSSHKey
#
class GenerateSSHKey:

    def __init__(self, lookup_plugin, passphrase):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin
        self.variables      = lookup_plugin.variables
        self.kwargs         = lookup_plugin.kwargs
        self.passphrase     = passphrase

        # set options
        self.opts = OptionsGenerateSSHKey(lookup_plugin)

        # create temp file
        self.tmpfile        = self.opts.get_tmp_filename()

        # create password file - not used by openssl
        # check comments in gen_pkcs8() method for more info
        self.pwdfile        = hlp.create_pwd_file(self.tmpfile, passphrase)

        # set a bunch of filenames for all different private/public keytypes
        self.filenames   = {
            "password"                  : "{}.pwd",
            "private"                   : "{}", # A
            "private_pkcs8"             : "{}.pkcs8", # B
            "private_openssh"           : "{}.openssh", # C
            "private_putty"             : "{}.ppk", # D
            "private_sshcom"            : "{}.sshcom", # E
            "public"                    : "{}.pub", # A
            "public_pem"                : "{}.pem.pub", # G
            "public_pkcs8"              : "{}.pkcs8.pub",  # B
            "public_rfc4716"            : "{}.rfc4716.pub", # F
            "fingerprint_sha256"        : "{}.pub.fingerprint.sha256", # A
            "fingerprint_sha256_clean"  : "{}.pub.fingerprint.sha256.clean", # A
            "fingerprint_sha256_art"    : "{}.pub.fingerprint.sha256.art", # A
            "fingerprint_md5"           : "{}.pub.fingerprint.md5", # A
            "fingerprint_md5_clean"     : "{}.pub.fingerprint.md5.clean", # A
            "fingerprint_md5_art"       : "{}.pub.fingerprint.md5.art", # A
            "fingerprint_putty"         : "{}.pub.fingerprint.putty", # D
        }


    # function to generate sshkeys
    def generate(self):

        # options shorthand
        o = self.opts.getall()

        msg.display("generating new SSH key; this may take a while")

        # prepare the temp folder
        self.check_versions()

        #
        # SUPPORTED KEYTYPES
        # note that the default key can by any of the supported keytypes: rsa, ed25519
        # the default key determines which other keytypes are possible
        # these other keytypes are always generated; maybe this will be an improvement in the future
        # where a config setting allows you to select which (other) keytypes you wish to generate
        # so as to increase performance and only run these processes when requested
        # +=======================================+
        # | DESC      :   PRI | PUB | FIP | # | X |
        # +=======================================+
        # | default   :    1  |  1  |  6  | 8 | A |
        # | pkcs8     :    1  |  1  |     | 2 | B |
        # | openssh   :    1  |     |     | 1 | C |
        # | putty     :    1  |     |  1  | 2 | D |
        # | sshcom    :    1  |     |     | 1 | E |
        # | rfc4716   :       |  1  |     | 1 | F |
        # | pem       :       |  1  |     | 1 | G |
        # +=======================================+
        # TOTAL                            16
        #

        # set list of keytypes to generate
        # openssh should be run last, because it modifies the orignal key file, which is why it is not in the list yet
        gen         = [ "default", "rfc4716" ]

        # check if pem format can be created
        if o['sshkey_type'] != "ed25519":
            gen.append("pem")

        # check if openssl/pkcs8 key can be created
        if o['sshkey_pkcs8_enabled'] and o['sshkey_type'] != "ed25519":
            gen.append("pkcs8")

        # check if putty/sshcom keys can be created
        if o['sshkey_putty_enabled']:
            gen.append("putty")

            # check if sshcom keys can be created
            if o['sshkey_type'] != "ed25519":
                gen.append("sshcom")

        # set empty result set
        result = {}
        
        # generate all available types
        for g in gen:

            # get generator name
            gname = "gen_{}".format(g)
            f = getattr(self, gname)

            # directly merge results into result dict
            result = self.opts.merge(result, f())

        # always run openssh at the end because it changes the original keyfile
        result = self.opts.merge(result, self.gen_openssh())

        # add key type and bits to result for future reference
        result['private_keytype'] = o['sshkey_type']
        result['password'] = self.passphrase
        if o['sshkey_type'] == 'ed25519':
            result['private_keybits'] = '256'
        else:
            result['private_keybits'] = o['sshkey_bits']

        # return
        return result

    # generate default keyfiles
    def gen_default(self):

        # set filenames
        file_key    = self.filenames["private"].format(self.tmpfile)
        file_pub    = self.filenames["public"].format(self.tmpfile)

        # merge arguments and command
        # bits are ignored for ed25519 keys
        cmd = [self.opts.get('sshkey_bin_keygen')]
        args = ["-t{0}".format(self.opts.get('sshkey_type')),
                "-b{0}".format(self.opts.get('sshkey_bits')),
                "-C{0}".format(self.opts.get('sshkey_comment')),
                "-f{0}".format(file_key),
                "-N{0}".format(self.passphrase)]
        cmd += args

        # run subprocess
        proc = Process("ssh-keygen", cmd).run()

        # read file contents
        result = {}
        result['private']   = hlp.get_file_contents(file_key)
        result['public']    = hlp.get_file_contents(file_pub)

        # generate fingerprints / bubble babble
        result = self.opts.merge(result, self.gen_fingerprints("md5", file_pub))
        result = self.opts.merge(result, self.gen_fingerprints("sha256", file_pub))
        result = self.opts.merge(result, self.gen_bubblebabble(file_pub))

        # return result
        return result

    # generate pkcs8 keyfiles
    def gen_pkcs8(self):
        
        # set filenames
        file_key    = self.filenames["private"].format(self.tmpfile)
        file_pub    = self.filenames["public"].format(self.tmpfile)
        file_pkcs8  = self.filenames["private_pkcs8"].format(self.tmpfile)

        # create password file
        # BEWARE: when supplying the SAME password file for both a -passin file:filename and -passout file:filename parameter,
        # openssl will use the first line as the passin password and the second line as the passout parameter
        # if the password file does not contain a second line, openssl will fail with the following message:
        #  Error reading password from BIO
        #  Error getting passwords
        # to avoid this, we write the same password to the password file twice. Since we're only using openssl to convert a
        # single key into multiple formats, this does not pose a security risk
        # to avoid confusing and prevent potential error with other processes requiring the password file, we generate a seperate one
        file_pwd    = hlp.create_pwd_file(self.opts.get_tmp_filename(), "{}\n{}".format(self.passphrase, self.passphrase))

        # merge arguments and command
        cmd = [self.opts.get('sshkey_bin_openssl')]
        args = ["pkcs8", "-topk8", "-v2", "des3",
                "-in", "{}".format(file_key),
                "-passin", "file:{}".format(file_pwd),
                "-out", "{}".format(file_pkcs8),
                "-passout", "file:{}".format(file_pwd)]
        cmd += args

        # run subprocess
        proc = Process("openssl", cmd).run()

        # read file contents
        result = {}
        result['private_pkcs8'] = hlp.get_file_contents(file_pkcs8)

        # generate public key
        cmd = [self.opts.get('sshkey_bin_keygen'),
               "-e", "-mPKCS8", "-f{}".format(file_pub)]
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()
        result['public_pkcs8'] = "\n".join(stdout)

        # return result
        return result

    # generate openssh keyfiles
    def gen_openssh(self):
        
        # set filenames
        file_key        = self.filenames["private"].format(self.tmpfile)

        # merge arguments and command
        cmd = [self.opts.get('sshkey_bin_keygen'),
               "-f{}".format(file_key),
               "-p", "-P{}".format(self.passphrase),
               "-N{}".format(self.passphrase),
               "-o",
               "-a", "100"]
        proc    = Process("ssh-keygen", cmd).run()

        # set result
        result = {}
        result['private_openssh'] = hlp.get_file_contents(file_key)

        # return result
        return result

    # generate putty keyfiles
    def gen_putty(self):

        # set filenames
        file_key        = self.filenames["private"].format(self.tmpfile)
        file_putty      = self.filenames["private_putty"].format(self.tmpfile)

        # merge arguments and command
        cmd = [self.opts.get('sshkey_bin_puttygen'),
               "{}".format(file_key),
               "-O", "private",
               "--old-passphrase", "{}".format(self.pwdfile),
               "--new-passphrase", "{}".format(self.pwdfile),
               "-o", "{}".format(file_putty),
               "-C", "{}".format(self.opts.get('sshkey_comment'))]
        proc = Process("puttygen", cmd).run()

        # set result
        result = {}
        result['private_putty'] = hlp.get_file_contents(file_putty)

        # generate putty fingerprint
        cmd = [self.opts.get('sshkey_bin_puttygen'),
               "{}".format(file_putty),
               "-O", "fingerprint"]
        proc = Process("puttygen", cmd).run()
        stdout  = proc.getstdout()
        result['fingerprint_putty'] = "\n".join(stdout)

        # return result
        return result

    # generate sshcom keyfiles
    def gen_sshcom(self):

        # set filenames
        file_key        = self.filenames["private"].format(self.tmpfile)
        file_sshcom     = self.filenames["private_sshcom"].format(self.tmpfile)

        # merge arguments and command
        cmd = [self.opts.get('sshkey_bin_puttygen'),
               "{}".format(file_key),
               "-O", "private-sshcom",
               "--old-passphrase", "{}".format(self.pwdfile),
               "--new-passphrase", "{}".format(self.pwdfile),
               "-o", "{}".format(file_sshcom),
               "-C", "{}".format(self.opts.get('sshkey_comment'))]
        proc = Process("puttygen", cmd).run()

        # set result
        result = {}
        result['private_sshcom'] = hlp.get_file_contents(file_sshcom)

        # return result
        return result

    # generate rfc4716 keyfiles
    def gen_rfc4716(self):
        
        # set filenames
        file_pub = self.filenames["public"].format(self.tmpfile)

        # merge arguments and command
        # setting a custom comment for this keytype is not supported
        cmd = [self.opts.get('sshkey_bin_keygen'),
               "-e", "-m", "RFC4716",
               "-f{}".format(file_pub)]
        proc    = Process("ssh-keygen", cmd).run()

        # set result
        result = {}
        stdout  = proc.getstdout()
        result['public_rfc4716'] = "\n".join(stdout)

        # return result
        return result

    # generate pem keyfiles
    def gen_pem(self):
        
        # set filenames
        file_pub = self.filenames["public"].format(self.tmpfile)

        # merge arguments and command
        cmd = [self.opts.get('sshkey_bin_keygen'),
               "-e", "-m", "PEM",
               "-f{}".format(file_pub)]
        proc    = Process("ssh-keygen", cmd).run()

        # set result
        result = {}
        stdout  = proc.getstdout()
        result['public_pem'] = "\n".join(stdout)

        # return result
        return result

    # generate fingerprints
    def gen_fingerprints(self, fptype, pubfile):

        # generate fingerprints - output sent to stdout
        cmd = [self.opts.get('sshkey_bin_keygen'),  # full path to binary
               "-l",                        # list fingerprint
               "-v",                        # list visual fingerprint
               "-E{}".format(fptype),       # fingerprint hash algorithm
               "-f{}".format(pubfile)]      # full path to public key

        # run process and catch stdout
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()
        fpline  = stdout.pop(0)

        # set results
        result = {}
        result['fingerprint_{}'.format(fptype)] = fpline
        result['fingerprint_{}_clean'.format(fptype)] = hlp.extract_fingerprint(fpline)
        result['fingerprint_{}_art'.format(fptype)] = "\n".join(stdout)

        # return
        return result

    # generate fingerprints
    def gen_bubblebabble(self, pubfile):

        # generate fingerprints - output sent to stdout
        cmd = [self.opts.get('sshkey_bin_keygen'),   # full path to binary
               "-B",                        # list bubble babble fingerprint
               "-f{}".format(pubfile)]      # full path to public key

        # run process and catch stdout
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()
        bbline  = stdout.pop(0)

        # set results
        result = {}
        result['fingerprint_bubblebabble'] = bbline
        result['fingerprint_bubblebabble_clean'] = hlp.extract_bubblebabble(bbline)

        # return
        return result


    # function to verify we have the right software versions
    def check_versions(self):

        # only check puttygen version if puttygen is enabled
        if self.opts.get('sshkey_putty_enabled'):

            msg.vvv("checking puttygen version")

            # merge arguments and command
            cmd = [self.opts.get('sshkey_bin_puttygen'),"--version",]
            proc = Process("puttygen", cmd).run()

            # regex version from first line
            stdout  = proc.getstdout()
            regex_putty = r"^.+(\d\.\d+)"
            match_putty = re.match(regex_putty, stdout[0])

            # sanity check
            if re.compile(regex_putty).groups < 1:
                msg.fail("could not find a valid puttygen version number in string [{}]".format(stdout[0]))

            # check versions
            versions        =  {'puttygen' : match_putty.group(1)}
            req_puttygen    = '0.72'

            # sanity check
            if version.parse(versions['puttygen']) < version.parse(req_puttygen):
                msg.fail("puttygen version [{}] is required; [{}] given".format(req_puttygen, versions['puttygen']))
            else:
                msg.vvv("puttygen version [{}] detected".format(versions['puttygen']))

        return True
