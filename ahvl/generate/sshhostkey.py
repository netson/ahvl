#
# import modules
#
from ahvl.options.generate.sshhostkey import OptionsGenerateSSHHostKey
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
# GenerateSSHHostKey
#
class GenerateSSHHostKey:

    def __init__(self, lookup_plugin):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin
        self.variables      = lookup_plugin.variables
        self.kwargs         = lookup_plugin.kwargs

        # set options
        self.opts = OptionsGenerateSSHHostKey(lookup_plugin)

        # create temp file
        self.tmpfile        = self.opts.get_tmp_filename()

        # set a bunch of filenames for all different private/public keytypes
        self.filenames = {
            "private"                   : "{}",
            "public"                    : "{}.pub",
            "fingerprint_sha256"        : "{}.pub.fingerprint.sha256",
            "fingerprint_sha256_clean"  : "{}.pub.fingerprint.sha256.clean",
            "fingerprint_sha256_art"    : "{}.pub.fingerprint.sha256.art",
            "fingerprint_md5"           : "{}.pub.fingerprint.md5",
            "fingerprint_md5_clean"     : "{}.pub.fingerprint.md5.clean",
            "fingerprint_md5_art"       : "{}.pub.fingerprint.md5.art",
            "dns_sha1"                  : "{}.pub.sshfp.sha1",
            "dns_sha1_clean"            : "{}.pub.sshfp.sha1.clean",
            "dns_sha256"                : "{}.pub.sshfp.sha256",
            "dns_sha256_clean"          : "{}.pub.sshfp.sha256.clean",
        }


    # generate ssh hostkeyfiles
    def generate(self):

        # options shorthand
        o = self.opts.getall()

        msg.display("generating new SSH host keys; this may take a while")

        #
        # SUPPORTED KEYTYPES
        # +=============================================+
        # | DESC      :   PRI | PUB | FIP | DNS | # | X |
        # +=============================================+
        # | rsa       :    1  |  1  |  6  |     | 8 | A |
        # | dsa       :    1  |  1  |  6  |     | 8 | B | - not supported
        # | ecdsa     :    1  |  1  |  6  |     | 8 | C | - not supported
        # | ed25519   :    1  |  1  |  6  |     | 8 | D |
        # +=============================================+
        # TOTAL                                  32
        #

        # set a bunch of filenames for all different private/public keytypes

        # set filenames
        file_key = self.filenames['private'].format(self.tmpfile)
        file_pub = self.filenames['public'].format(self.tmpfile)

        # set bits for key strength
        sw_rsa = {
            'medium': 2048,
            'strong': 4096,
        }
        sw_ed25519 = {
            'medium': 256,
            'strong': 256,
        }

        # set shorthand for keytype and strength
        t = o['sshhostkey_type']
        s = o['sshhostkey_strength']

        # get proper bits for selected keytype and strength
        if t == "rsa":
            b = sw_rsa.get(s)
        elif t == "ed25519":
            b = sw_ed25519.get(s)

        # merge arguments and command
        cmd = "{} -b {} -t {} -o -a 100 -f {} -N '' -C '{}'".format(o['sshhostkey_bin_keygen'], b, t, file_key, o['sshhostkey_comment'])
        proc = Process("ssh-keygen", cmd, shell=True).run()

        # set result keys
        result = {}
        result['private'] = hlp.get_file_contents(file_key)
        result['public']  = hlp.get_file_contents(file_pub)

        # generate fingerprints
        result = self.opts.merge(result, self.gen_fingerprints("md5", file_pub))
        result = self.opts.merge(result, self.gen_fingerprints("sha256", file_pub))
        result = self.opts.merge(result, self.gen_bubblebabble(file_pub))

        # generate and merge dns records
        # don't use the self.hostname variable for DNS, but the value given by the user
        result = self.opts.merge(result, self.gen_dns(file_pub))

        # add keybits; keytype is added to keyname itself in next step
        result['private_keybits'] = str(b)

        # rename keys
        #resultiterator = result.copy()
        #for k,v in resultiterator.items():
        #    nk = "{}_{}".format(self.opts.get('sshhostkey_type'), k)
        #    result[nk] = result.pop(k)

        # return
        return result

    # generate dns records
    def gen_dns(self, pubfile):

        # generate dns records - output sent to stdout
        cmd = [self.opts.get('sshhostkey_bin_keygen'),   # full path to binary
               "-r{}".format(self.opts.get('hostname')),     # hostname of dns records
               "-f{}".format(pubfile)]      # full path to public key

        #
        # SSHFP records consist of three things:
        # 
        # Algorithm
        #   1 - RSA
        #   2 - DSA
        #   3 - ECDSA
        #   4 - Ed25519
        # Fingerprint type
        #   1 - SHA-1
        #   2 - SHA-256
        # Fingerprint (in hex)
        #
        # EXAMPLE:
        # [root@localhost ~]# ssh-keygen -r my.domain.com -f ./mykey.pub
        # example.com IN SSHFP 4 1 de3dec1fb5eadf130396a60607f5baa6ace831e8
        # example.com IN SSHFP 4 2 a0a4d61227b08addd0d685ded8e475c396831e6d91ab3ac1adf536425fab431f
        #

        # run process and catch stdout
        proc    = Process("ssh-keygen", cmd).run()
        stdout  = proc.getstdout()

        # set known algorithms and fingerprint types
        algorithms = {
            "1": "rsa",
            "2": "dsa",
            "3": "ecdsa",
            "4": "ed25519",
        }
        fptypes = {
            "1": "sha1",
            "2": "sha256",
        }

        # find algorithm and fptype for each output line
        result = {}
        for l in stdout:

            # split items on space and extract info
            items    = l.split(" ")
            alg      = algorithms[items[3]] # not added to key, as that is done elsewhere
            fpt      = fptypes[items[4]]
            clean    = items[3:]
            dnsname  = "dns_{}".format(fpt)
            dnsclean = "dns_{}_clean".format(fpt)

            # set dns records
            result[dnsname]  = " ".join(items)
            result[dnsclean] = " ".join(clean)

        # return
        return result

    # generate fingerprints
    def gen_fingerprints(self, fptype, pubfile):

        # generate fingerprints - output sent to stdout
        cmd = [self.opts.get('sshhostkey_bin_keygen'),   # full path to binary
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
        cmd = [self.opts.get('sshhostkey_bin_keygen'),   # full path to binary
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
