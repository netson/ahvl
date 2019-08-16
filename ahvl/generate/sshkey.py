#
# import modules
#
from ahvl.options.generatesshkey import OptionsGenerateSSHKey
from ahvl.process import Process
from ansible.utils.display import Display
import re
import os

#
# ansible display
#
display = Display()

#
# GenerateSSHKey
#
class GenerateSSHKey:

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        #
        # options
        #
        self.opts = OptionsGenerateSSHKey(variables, lookup_plugin, **kwargs)

    # function to generate sshkeys
    def generate(self):

        # get common info for keys
        username = self.opts.get('key_username')
        password = self.opts.get('key_password')
        tempfile = self.opts.get_tmp_filename()

        # SUPPORTED KEYTYPES
        # note that the default key can by any of the supported keytypes: rsa, dsa, ecdsa, ed25519
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

        # set list of keys to generate
        gen         = [ "default", "rfc4716" ] # openssh should be run last, because it modifies the orignal key file

        # set a bunch of filenames for all different private/public keytypes
        filenames   = {
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

        # check if pem format can be created
        if self.opts.get('key_type') != "ed25519":
            gen.append("pem")

        # check if openssl/pkcs8 key can be created
        if self.opts.get('pkcs8_enabled') and self.opts.get('key_type') != "ed25519":
            gen.append("pkcs8")

        # check if putty/sshcom keys can be created
        if self.opts.get('putty_enabled'):

            # putty version check
            putty_version = self.putty_get_version()
            if float(putty_version) < 0.71 and self.opts.get('key_type') == "ed25519":
                display.display("skipping putty key type while ed25519 support wasn't added to putty until version 0.71; running version [{}]".format(putty_version))
            else:
                gen.append("putty")

            # check if sshcom keys can be created
            if self.opts.get('key_type') != "ed25519":
                gen.append("sshcom")

        # generate all available types
        result = {}
        for g in gen:

            # get generator name
            gname = "gen_{}".format(g)
            f = getattr(self, gname)

            # directly merge results into result dict
            result = self.opts.merge(result, f(username, password, tempfile, filenames))

        # always run openssh at the end because it changes the original keyfile
        result = self.opts.merge(result, self.gen_openssh(username, password, tempfile, filenames))

        # delete temp files
        filename = "ssh_{}_{}".format(self.opts.hostname.replace(".", "_"), username.replace("@", "_at_"))
        self.cleanup(tempfile, filename, result, filenames)

        # add key type and bits to result for future reference
        result['private_keytype'] = self.opts.get('key_type')
        if self.opts.get('key_type') == 'ed25519':
            result['private_keybits'] = '256'
        else:
            result['private_keybits'] = self.opts.get('key_bits')

        # return
        return result

    # generate default keyfiles
    def gen_default(self, username, password, tempfile, filenames):

        # set filenames
        file_key    = filenames["private"].format(tempfile)
        file_pub    = filenames["public"].format(tempfile)

        # merge arguments and command
        # bits are ignored for ed25519 keys
        cmd = [self.opts.get('bin_keygen')]
        args = ["-t{0}".format(self.opts.get('key_type')),
                "-b{0}".format(self.opts.get('key_bits')),
                "-C{0}".format(self.opts.get('key_comment')),
                "-f{0}".format(file_key),
                "-N{0}".format(password)]
        cmd += args

        # run subprocess
        proc = Process("ssh-keygen", cmd).run()

        # read file contents
        result = {}
        result['private']   = self.opts.get_file_contents(file_key)
        result['public']    = self.opts.get_file_contents(file_pub)

        # generate fingerprints / bubble babble
        result = self.opts.merge(result, self.gen_fingerprints("md5", file_pub))
        result = self.opts.merge(result, self.gen_fingerprints("sha256", file_pub))
        result = self.opts.merge(result, self.gen_bubblebabble(file_pub))

        # return result
        return result

    # generate pkcs8 keyfiles
    def gen_pkcs8(self, username, password, tempfile, filenames):
        
        # set filenames
        file_key    = filenames["private"].format(tempfile)
        file_pub    = filenames["public"].format(tempfile)
        file_pkcs8  = filenames["private_pkcs8"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_openssl')]
        args = ["pkcs8", "-topk8", "-v2", "des3",
                "-in", "{}".format(file_key),
                "-passin", "pass:{}".format(password),
                "-out", "{}".format(file_pkcs8),
                "-passout", "pass:{}".format(password)]
        cmd += args

        # run subprocess
        proc = Process("openssl", cmd).run()

        # read file contents
        result = {}
        result['private_pkcs8'] = self.opts.get_file_contents(file_pkcs8)

        # generate public key
        cmd = [self.opts.get('bin_keygen'),
               "-e", "-mPKCS8", "-f{}".format(file_pub)]
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()
        result['public_pkcs8'] = "\n".join(stdout)

        # return result
        return result

    # generate openssh keyfiles
    def gen_openssh(self, username, password, tempfile, filenames):
        
        # set filenames
        file_key        = filenames["private"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_keygen'),
               "-f{}".format(file_key),
               "-p", "-P{}".format(password),
               "-N{}".format(password),
               "-o",
               "-a", "100"]
        proc    = Process("ssh-keygen", cmd).run()

        # set result
        result = {}
        result['private_openssh'] = self.opts.get_file_contents(file_key)

        # return result
        return result

    # generate putty keyfiles
    def gen_putty(self, username, password, tempfile, filenames):

        # set pwd file
        pwdfile         = self.putty_create_pwd_file(password)

        # set filenames
        file_key        = filenames["private"].format(tempfile)
        file_putty      = filenames["private_putty"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_puttygen'),
               "{}".format(file_key),
               "-O", "private",
               "--old-passphrase", "{}".format(pwdfile),
               "--new-passphrase", "{}".format(pwdfile),
               "-o", "{}".format(file_putty),
               "-C", "{}".format(username)]
        proc = Process("puttygen", cmd).run()

        # set result
        result = {}
        result['private_putty'] = self.opts.get_file_contents(file_putty)

        # generate putty fingerprint
        cmd = [self.opts.get('bin_puttygen'),
               "{}".format(file_putty),
               "-O", "fingerprint"]
        proc = Process("puttygen", cmd).run()
        stdout  = proc.getstdout()
        result['fingerprint_putty'] = "\n".join(stdout)

        # destroy pwd file
        self.putty_destroy_pwd_file(pwdfile)

        # return result
        return result

    # generate sshcom keyfiles
    def gen_sshcom(self, username, password, tempfile, filenames):

        # set pwd file
        pwdfile = self.putty_create_pwd_file(password)

        # set filenames
        file_key        = filenames["private"].format(tempfile)
        file_sshcom     = filenames["private_sshcom"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_puttygen'),
               "{}".format(file_key),
               "-O", "private-sshcom",
               "--old-passphrase", "{}".format(pwdfile),
               "--new-passphrase", "{}".format(pwdfile),
               "-o", "{}".format(file_sshcom),
               "-C", "{}".format(username)]
        proc = Process("puttygen", cmd).run()

        # set result
        result = {}
        result['private_sshcom'] = self.opts.get_file_contents(file_sshcom)

        # destroy pwd file
        self.putty_destroy_pwd_file(pwdfile)

        # return result
        return result

    # generate rfc4716 keyfiles
    def gen_rfc4716(self, username, password, tempfile, filenames):
        
        # set filenames
        file_pub = filenames["public"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_keygen'),
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
    def gen_pem(self, username, password, tempfile, filenames):
        
        # set filenames
        file_pub = filenames["public"].format(tempfile)

        # merge arguments and command
        cmd = [self.opts.get('bin_keygen'),
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
        cmd = [self.opts.get('bin_keygen'),   # full path to binary
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
        result['fingerprint_{}_clean'.format(fptype)] = self.opts.extract_fingerprint(fpline)
        result['fingerprint_{}_art'.format(fptype)] = "\n".join(stdout)

        # return
        return result

    # generate fingerprints
    def gen_bubblebabble(self, pubfile):

        # generate fingerprints - output sent to stdout
        cmd = [self.opts.get('bin_keygen'),   # full path to binary
               "-B",                        # list bubble babble fingerprint
               "-f{}".format(pubfile)]      # full path to public key

        # run process and catch stdout
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()
        bbline  = stdout.pop(0)

        # set results
        result = {}
        result['fingerprint_bubblebabble'] = bbline
        result['fingerprint_bubblebabble_clean'] = self.opts.extract_bubblebabble(bbline)

        # return
        return result

    # function to get putty version
    def putty_get_version(self):

        # merge arguments and command
        cmd = [self.opts.get('bin_puttygen'),"--version",]
        proc = Process("puttygen", cmd).run()

        # regex version from first line
        stdout  = proc.getstdout()
        version = re.match('^.+(\d\.\d+)', stdout[0])
        display.vvv("puttygen version [{}]".format(version.group(1)))
        return version.group(1)

    # generate putty password file
    def putty_create_pwd_file(self, password):

        # create tmp file with password for putty
        tmpfile = self.opts.get_tmp_filename()
        file    = open(tmpfile, "w+")
        file.write(password)
        file.close()

        # return filepath
        return tmpfile

    # destroy putty password file
    def putty_destroy_pwd_file(self, pwdfile):

        # destroy
        if os.path.isfile(pwdfile):
                os.remove(pwdfile)

    # function to cleanup
    def cleanup(self, tempfile, filename, sshkeys, filenames):

        # delete tmp files
        self.opts.delete_tmp_files(tempfile, filenames)

        # remove tmpdir
        self.opts.delete_tmp_dir(os.path.dirname(tempfile))
