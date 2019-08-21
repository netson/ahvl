#
# import modules
#
from ahvl.options.generate.gpgkey import OptionsGenerateGPGKey
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
# GenerateGPGKey
#
class GenerateGPGKey:

    def __init__(self, lookup_plugin, passphrase, passphrase2=''):

        # set lookup plugin
        self.lookup_plugin  = lookup_plugin
        self.variables      = lookup_plugin.variables
        self.kwargs         = lookup_plugin.kwargs
        self.passphrase     = passphrase
        self.passphrase2    = passphrase2 # used only when generating set of backup keys (i.e. duplicity)

        # set options
        self.opts = OptionsGenerateGPGKey(lookup_plugin)

        # create password files
        self.tmpfile        = self.opts.get_tmp_filename()
        self.pwdfile        = hlp.create_pwd_file(self.tmpfile, passphrase)
        self.tmpfile2       = self.opts.get_tmp_filename()
        self.pwdfile2       = hlp.create_pwd_file(self.tmpfile2, passphrase2)


    # generate gpg keyfiles
    def generate(self):

        # options shorthand
        o = self.opts

        msg.display("generating new set of GPG keys [{}]; this may take a while".format(self.opts.get('gpgkey_keyset')))

        # prepare the temp folder
        self.check_versions()
        self.create_gpg_conf()
        self.init_gnupg_dir()

        # determine type of keyset to generate
        if self.opts.get('gpgkey_keyset') == 'backup':
            result = self.generate_backup()
        else:
            result = self.generate_regular()

        # return
        return result


    # generate regular gpg key set
    def generate_regular(self):

        # set empty result
        result = {}

        #
        # generate the master key
        #
        self.generate_key('cert', pwdfile=self.pwdfile)
        master_sec_info = self.get_key_info(keytype='secret', usage='cert', mapping='regular')
        master_pub_info = self.get_key_info(keytype='public', usage='cert', mapping='regular')
        master_fpr      = master_sec_info['master_cert_sec_fingerprint']
        result          = self.opts.merge(result, master_sec_info)
        result          = self.opts.merge(result, master_pub_info)

        #
        # generate the sign subkey - provide the fingerprint of the master
        #
        self.generate_key('sign', pwdfile=self.pwdfile, fpr=master_fpr)
        sign_sec_info   = self.get_key_info(keytype='secret', usage='sign', mapping='regular', fpr=master_fpr)
        sign_fpr        = sign_sec_info['subkey_sign_sec_fingerprint']
        result          = self.opts.merge(result, sign_sec_info)

        #
        # generate the encr subkey - provide the fingerprint of the master
        #
        self.generate_key('encr', pwdfile=self.pwdfile, fpr=master_fpr)
        encr_sec_info   = self.get_key_info(keytype='secret', usage='encr', mapping='regular', fpr=master_fpr)
        encr_fpr        = encr_sec_info['subkey_encr_sec_fingerprint']
        result          = self.opts.merge(result, encr_sec_info)

        #
        # generate the auth subkey - provide the fingerprint of the master
        #
        self.generate_key('auth', pwdfile=self.pwdfile, fpr=master_fpr)
        auth_sec_info   = self.get_key_info(keytype='secret', usage='auth', mapping='regular', fpr=master_fpr)
        auth_fpr        = auth_sec_info['subkey_auth_sec_fingerprint']
        result          = self.opts.merge(result, auth_sec_info)

        #
        # export the keys so they can be added to the result
        #
        msg.vvvv("exporting keys")
        result['master_cert_sec_key_armored'] = self.export_keys('sec', master_fpr, self.pwdfile)
        result['master_cert_pub_key_armored'] = self.export_keys('pub', master_fpr, self.pwdfile)
        result['subkey_sign_sec_key_armored'] = self.export_keys('ssb', sign_fpr, self.pwdfile)
        result['subkey_encr_sec_key_armored'] = self.export_keys('ssb', encr_fpr, self.pwdfile)
        result['subkey_auth_sec_key_armored'] = self.export_keys('ssb', auth_fpr, self.pwdfile)

        #
        # add the remaining info from the class options
        #
        msg.vvvv("adding remaining information to result")
        result['master_cert_sec_keytype'] = self.opts.get('gpgkey_type')
        result['master_cert_sec_keyuid'] = self.opts.get('gpgkey_uid')
        result['master_cert_sec_password'] = self.passphrase

        # return
        return result


    # generate regular gpg key set
    def generate_backup(self):

        # set empty result
        result = {}

        #
        # SIGN - generate the master key
        #
        self.generate_key('cert', pwdfile=self.pwdfile, uidprefix="backup_sign")
        sign_master_sec_info    = self.get_key_info(keytype='secret', usage='cert', mapping='backup_sign')
        sign_master_pub_info    = self.get_key_info(keytype='public', usage='cert', mapping='backup_sign')
        sign_master_fpr         = sign_master_sec_info['sign_master_cert_sec_fingerprint']
        result                  = self.opts.merge(result, sign_master_sec_info)
        result                  = self.opts.merge(result, sign_master_pub_info)

        #
        # SIGN - generate the sign subkey - provide the fingerprint of the master
        #
        self.generate_key('sign', pwdfile=self.pwdfile, fpr=sign_master_fpr)
        sign_sec_info           = self.get_key_info(keytype='secret', usage='sign', mapping='backup_sign', fpr=sign_master_fpr)
        sign_fpr                = sign_sec_info['sign_subkey_sign_sec_fingerprint']
        result                  = self.opts.merge(result, sign_sec_info)

        #
        # ENCR - generate the master key
        #
        self.generate_key('cert', pwdfile=self.pwdfile2, uidprefix="backup_encr")
        encr_master_sec_info    = self.get_key_info(keytype='secret', usage='cert', mapping='backup_encr')
        encr_master_pub_info    = self.get_key_info(keytype='public', usage='cert', mapping='backup_encr')
        encr_master_fpr         = encr_master_sec_info['encr_master_cert_sec_fingerprint']
        result                  = self.opts.merge(result, encr_master_sec_info)
        result                  = self.opts.merge(result, encr_master_pub_info)

        #
        # ENCR - generate the encr subkey - provide the fingerprint of the master
        #
        self.generate_key('encr', pwdfile=self.pwdfile2, fpr=encr_master_fpr)
        encr_sec_info           = self.get_key_info(keytype='secret', usage='encr', mapping='backup_encr', fpr=encr_master_fpr)
        encr_fpr                = encr_sec_info['encr_subkey_encr_sec_fingerprint']
        result                  = self.opts.merge(result, encr_sec_info)

        #
        # sign encryption key
        # we should sign the encr master key, not the subkey
        #
        msg.vvvv("signing encrypt key with sign key")
        self.sign_key(self.pwdfile, sign_with_key=sign_fpr, fpr_to_sign=encr_master_fpr)

        #
        # export the keys so they can be added to the result
        #
        msg.vvvv("exporting sign keys")
        result['sign_master_cert_sec_key_armored']  = self.export_keys('sec', sign_master_fpr, self.pwdfile)
        result['sign_master_cert_pub_key_armored']  = self.export_keys('pub', sign_master_fpr, self.pwdfile)
        result['sign_subkey_sign_sec_key_armored']  = self.export_keys('ssb', sign_fpr, self.pwdfile)
        msg.vvvv("exporting encr keys")
        result['encr_master_cert_sec_key_armored']  = self.export_keys('sec', encr_master_fpr, self.pwdfile2)
        result['encr_master_cert_pub_key_armored']  = self.export_keys('pub', encr_master_fpr, self.pwdfile2)
        result['encr_subkey_encr_sec_key_armored']  = self.export_keys('ssb', encr_fpr, self.pwdfile2)

        #
        # add the remaining info from the class options
        #
        msg.vvvv("adding remaining information to result")
        result['sign_master_cert_sec_keytype']      = self.opts.get('gpgkey_type')
        result['sign_master_cert_sec_keyuid']       = self.opts.get('gpgkey_uid')
        result['sign_master_cert_sec_password']     = self.passphrase
        result['encr_master_cert_sec_keytype']      = self.opts.get('gpgkey_type')
        result['encr_master_cert_sec_keyuid']       = self.opts.get('gpgkey_uid')
        result['encr_master_cert_sec_password']     = self.passphrase2

        # return
        return result


    # function to verify we have the right gnupg2 version
    def check_versions(self):

        msg.vvvv("checking gnupg and libgcrypt versions")

        # set command
        cmd = [self.opts.get('gpgkey_bin')]
        args = ["--version"]
        cmd += args

        # run subprocess
        proc = Process("gpg", cmd).run()
        stdout = proc.getstdout()

        # find gpg version
        regex_gpg = r"gpg\s+\(GnuPG\)\s+(\d+\.\d+\.?\d*)$"
        match_gpg = re.match(regex_gpg, stdout[0])

        # sanity check
        if re.compile(regex_gpg).groups < 1:
            msg.fail("could not find a valid gpg version number in string [{}]".format(stdout[0]))

        # find libgcrypt version
        regex_libgcrypt = r"libgcrypt\s+(\d+\.\d+\.?\d*)$"
        match_libgcrypt = re.match(regex_libgcrypt, stdout[1])

        # sanity check
        if re.compile(regex_libgcrypt).groups < 1:
            msg.fail("could not find a valid libgcrypt version number in string [{}]".format(stdout[1]))

        # check versions
        versions        =  {'gpg'       : match_gpg.group(1),
                            'libgcrypt' : match_libgcrypt.group(1),
                           }
        req_gpg         = '2.1.17'
        req_libgcrypt   = '1.8.1'

        # sanity check
        if version.parse(versions['gpg']) < version.parse(req_gpg) or version.parse(versions['libgcrypt']) < version.parse(req_libgcrypt):
            msg.fail("gpg version [{}] and libgcrypt version [{}] are required; [{}] and [{}] given".format(req_gpg, req_libgcrypt, versions['gpg'], versions['libgcrypt']))
        else:
            msg.vvvv("gnupg version [{}] and libgcrypt version [{}] detected".format(versions['gpg'], versions['libgcrypt']))

        return True


    # function to write a gpg.conf file
    def create_gpg_conf(self):

        msg.vvv("creating gpg.conf")

        # set configuration
        lines   = self.opts.get('gpgkey_conf')
        gpgconf = ""
        for l in lines:
            gpgconf = "{}\n{}".format(gpgconf, l)

        # write config file
        file    = "{}{}".format(self.opts.get_tmp_dir(),'gpg.conf')
        hlp.write_tmp_file(file, gpgconf)


    # function to initialize the gnupg2 homedir
    def init_gnupg_dir(self):

        # simply running the list command will make gnupg create the trustdb etc
        cmd = [self.opts.get('gpgkey_bin')]
        args = self.get_publist_args()
        cmd += args

        # run subprocess; ignore any output, even though gpg sends the init messages to stderr
        proc = Process("gpg", cmd, failonstderr=False).run()


    # get key curve for Ed25519 keys
    def get_key_curvebits(self, usage):

        #
        # KEY USAGE & ALGORITHMS:
        #
        # the value of the option [gpgkey_type] determines which combination of key-usage and algo are selected
        #
        # supported algorithms are:         rsa|ed25519|cv25519
        # supported key usage values are:   cert|sign|auth|encr
        #
        # supported combinations are:
        # +-----------+------+------+------+------+
        # | algorithm | cert | sign | auth | encr |
        # +-----------+------+------+------+------+
        # | rsa       | yes  | yes  | yes  | yes  |
        # | ed25519   | yes  | yes  | yes  | no   |
        # | cv25519   | no   | no   | no   | yes  |
        # +-----------+------+------+------+------+
        #
        # DEFAULT KEY SETUP:
        #
        # This module will always generate a set of 4 keys:
        # 1 master key [cert]
        # - subkey for signing [sign]
        # - subkey for authorization [auth]
        # - subkey for encryptio [encr]
        #

        # check key type
        if self.opts.get('gpgkey_type') == 'ed25519' and usage == 'encr':
            return 'cv25519'
        elif self.opts.get('gpgkey_type') == 'ed25519':
            return 'ed25519'
        else:
            return 'rsa{}'.format(self.opts.get('gpgkey_bits'))


    # get cmd arguments
    def get_generate_args(self, usage, pwdfile, fpr=None, uidprefix=None):

        # set quick argument
        quick = {
            'cert'  : "generate-key",
            'auth'  : "add-key",
            'sign'  : "add-key",
            'encr'  : "add-key",
        }

        # uid or fpr
        # uid for master key, fpr for subkeys
        if fpr is not None:
            uidfpr = fpr
        else:
            uidfpr = self.opts.get('gpgkey_uid')

            # if generating a backup keyset, always prepend the uid
            if uidprefix is not None:
                uidfpr = "[{}] {}".format(uidprefix, uidfpr)

        # set arguments
        args = ['--batch',
                '--homedir={}'.format(self.opts.get_tmp_dir()),
                '--passphrase-file={}'.format(pwdfile),
                '--pinentry-mode=loopback',
                '--cert-digest-algo={}'.format(self.opts.get('gpgkey_digest')),
                '--digest-algo={}'.format(self.opts.get('gpgkey_digest')),
                '--s2k-cipher-algo={}'.format(self.opts.get('gpgkey_s2k_cipher')),
                '--s2k-digest-algo={}'.format(self.opts.get('gpgkey_s2k_digest')),
                '--s2k-mode={}'.format(self.opts.get('gpgkey_s2k_mode')),
                '--s2k-count={}'.format(self.opts.get('gpgkey_s2k_count')),
                '--quick-{}'.format(quick.get(usage)),
                '{}'.format(uidfpr),
                '{}'.format(self.get_key_curvebits(usage)),
                '{}'.format(usage),
                '{}'.format(self.opts.get('gpgkey_expirationdate')),
               ]

        return args


    # get publist args
    def get_publist_args(self):

        # arguments to list public keys
        return ['--homedir={}'.format(self.opts.get_tmp_dir()),
                '--list-keys',
               '--with-colons',
               ]


    # get seclist args
    def get_seclist_args(self):

        # arguments to list secret keys
        return ['--homedir={}'.format(self.opts.get_tmp_dir()),
                '--list-secret-keys',
                '--with-colons',
               ]


    # get signkey args
    def get_signkey_args(self, pwdfile, sign_with_key, fpr_to_sign):

        # arguments to sign keys
        # the [names] option (see man gpg2 | grep -na10 quick\-sign\-key)
        # is not required, as we're signing all subkeys
        return ['--homedir={}'.format(self.opts.get_tmp_dir()),
                '--default-key={}'.format(sign_with_key),
                '--passphrase-file={}'.format(pwdfile),
                '--pinentry-mode=loopback',
                '--quick-sign-key',
                '{}'.format(fpr_to_sign),
               ]


    # generate key
    def generate_key(self, usage, pwdfile, fpr=None, uidprefix=None):

        # create the command to generate a new master key
        cmd = [self.opts.get('gpgkey_bin')]
        args = self.get_generate_args(usage, pwdfile, fpr, uidprefix)
        cmd += args

        # run subprocess; catch the output but don't fail on stderr as gnupg outputs key creation details to stderr instead of stdout
        proc = Process("gpg", cmd, failonstderr=False).run()

        return True


    def sign_key(self, pwdfile, sign_with_key, fpr_to_sign):

        # create the command to sign the key
        cmd = [self.opts.get('gpgkey_bin')]
        args = self.get_signkey_args(pwdfile=pwdfile, sign_with_key=sign_with_key, fpr_to_sign=fpr_to_sign)
        cmd += args

        # run subprocess; catch the output but don't fail on stderr as gnupg outputs key creation details to stderr instead of stdout
        proc = Process("gpg", cmd, failonstderr=False).run()

        return True


    # export keys
    # unarmored keys are not exported; since they are binary the data might get scrambled
    def export_keys(self, ltype, fpr, pwdfile):

        # set keyfiles
        ascfile = "{}{}".format(self.opts.get_tmp_filename(),'.asc')

        # set export type
        if ltype == 'sec':
            exp = '-secret-keys'
        elif ltype == 'ssb':
            exp = '-secret-subkeys'
        else:
            exp = ''

        # set base command
        cmd = [self.opts.get('gpgkey_bin')]
        args = ['--homedir={}'.format(self.opts.get_tmp_dir()),
                '--passphrase-file={}'.format(pwdfile),
                '--pinentry-mode=loopback',
                '--quiet',
                '--armor',
                '--export{}'.format(exp),
                '{}'.format(fpr),
                #'--output={}'.format(ascfile) - output to stdout instead
               ]
        cmd += args

        # output unencrypted file
        proc = Process("gpg", cmd, failonstderr=False).run()

        # return stdout as it contains the armored key
        return proc.stdout


    # fetch key information
    def get_key_info(self, keytype, usage, mapping, fpr=None):

        msg.vvvv("attempt to extract key info from generated keys [{}] with usage [{}]".format(keytype, usage))

        # create the command to generate a new master key
        cmd = [self.opts.get('gpgkey_bin')]
        listargs = self.get_seclist_args() if keytype == 'secret' else self.get_publist_args()
        cmd += listargs

        # run subprocess; catch the output but don't fail on stderr as gnupg outputs key creation details to stderr instead of stdout
        proc = Process("gpg", cmd, failonstderr=False).run()

        #
        # SAMPLE DATA
        #
        # sec:u:256:22:41343326127FD34F:1566067845:::u:::cC:::+::ed25519:::0:
        # fpr:::::::::0D18E4B6B2698560729D00CE41343326127FD34F:
        # grp:::::::::54AA357FD85BA4D4B7CE86016A3734F00B1BDD07:
        # uid:u::::1566067845::00B9F0DC33EE293CC1E687FFA54A5EA805FD78F8::testing145 (TESTINGCOMM) <test@netson.nld>::::::::::0:
        #

        #
        # line types
        #
        # *** Field 1 - Type of record
        # 
        #     - pub :: Public key
        #     - crt :: X.509 certificate
        #     - crs :: X.509 certificate and private key available
        #     - sub :: Subkey (secondary key)
        #     - sec :: Secret key
        #     - ssb :: Secret subkey (secondary key)
        #     - uid :: User id
        #     - uat :: User attribute (same as user id except for field 10).
        #     - sig :: Signature
        #     - rev :: Revocation signature
        #     - rvs :: Revocation signature (standalone) [since 2.2.9]
        #     - fpr :: Fingerprint (fingerprint is in field 10)
        #     - pkd :: Public key data [*]
        #     - grp :: Keygrip
        #     - rvk :: Revocation key
        #     - tfs :: TOFU statistics [*]
        #     - tru :: Trust database information [*]
        #     - spk :: Signature subpacket [*]
        #     - cfg :: Configuration data [*]
        # 
        #     Records marked with an asterisk are described at [[*Special%20field%20formats][*Special fields]].        #
        #

        #
        # *** Field 12 - Key capabilities
        # 
        #     The defined capabilities are:
        # 
        #     - e :: Encrypt
        #     - s :: Sign
        #     - c :: Certify
        #     - a :: Authentication
        #     - ? :: Unknown capability
        # 
        #     A key may have any combination of them in any order.  In addition
        #     to these letters, the primary key has uppercase versions of the
        #     letters to denote the _usable_ capabilities of the entire key, and
        #     a potential letter 'D' to indicate a disabled key.
        #

        # determine which codes to look for
        if keytype == 'secret' and usage == 'cert':
            ltype = 'sec' # secret master key
        elif keytype == 'secret':
            ltype = 'ssb'
        elif keytype == 'public' and usage == 'cert':
            ltype = 'pub'
        else:
            ltype = 'sub'

        if usage == 'cert':
            lcapb = 'c'
        elif usage == 'sign':
            lcapb = 's'
        elif usage == 'auth':
            lcapb = 'a'
        else:
            lcapb = 'e'

        #
        # FIELD TYPES:
        #
        # - Field 1 - Type of record
        # - Field 2 - Validity
        # - Field 3 - Key length
        # - Field 4 - Public key algorithm
        # - Field 5 - KeyID
        # - Field 6 - Creation date
        # - Field 7 - Expiration date
        # - Field 8 - Certificate S/N, UID hash, trust signature info
        # - Field 9 -  Ownertrust
        # - Field 10 - User-ID
        # - Field 11 - Signature class
        # - Field 12 - Key capabilities
        # - Field 13 - Issuer certificate fingerprint or other info
        # - Field 14 - Flag field
        # - Field 15 - S/N of a token
        # - Field 16 - Hash algorithm
        # - Field 17 - Curve name
        # - Field 18 - Compliance flags
        # - Field 19 - Last update
        # - Field 20 - Origin
        # - Field 21 - Comment
        #

        # set empty result
        tmpresult = {}

        # determine the correct line
        correct_line = False
        main_lines = ['sec','ssb','pub','sub']
        follow_lines = ['fpr','grp','uid']

        # indexes start at 0
        # main parts are for main_lines only
        mainparts = {
            'type'              : 0,
            'key_length'        : 2,
            'pubkey_algorithm'  : 3,
            'keyid'             : 4,
            'creationdate'      : 5,
            'expirationdate'    : 6,
            'key_capabilities'  : 11,
            'hash_algorithm'    : 15,
            'curve_name'        : 16,
        }

        # indexes start at 0
        # follow parts for follow_lines only
        followparts = {
            'type'              : 0,
            'userid'            : 9, # this is the fingerprint for fpr records and the keygrip for grp records
        }

        #
        # 9.1.  Public-Key Algorithms
        # 
        #       ID           Algorithm
        #       --           ---------
        #       1          - RSA (Encrypt or Sign) [HAC]
        #       2          - RSA Encrypt-Only [HAC]
        #       3          - RSA Sign-Only [HAC]
        #       16         - Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
        #       17         - DSA (Digital Signature Algorithm) [FIPS186] [HAC]
        #       18         - Reserved for Elliptic Curve
        #       19         - Reserved for ECDSA
        #       20         - Reserved (formerly Elgamal Encrypt or Sign)
        #       21         - Reserved for Diffie-Hellman (X9.42,
        #                    as defined for IETF-S/MIME)
        #       22         - Ed25519
        #       100 to 110 - Private/Experimental algorithm
        #
        pubkeys = {
            '1'                 : 'RSA (Encrypt or Sign)',
            '2'                 : 'RSA Encrypt-Only',
            '3'                 : 'RSA Sign-Only',
            '16'                : 'Elgamal (Encrypt-Only)',
            '17'                : 'DSA [FIPS186]',
            '18'                : 'Cv25519',
            '22'                : 'Ed25519',
        }

        msg.vvvv("looping through key details")

        # loop through lines
        for l in proc.getstdout():

            #print("line: {}".format(l))
            # split line into pieces
            pieces = l.split(":")

            # get current type
            ctype = pieces[mainparts.get('type')]

            # check for usage/capabilities
            if ctype in main_lines:
                ccapb = pieces[mainparts.get('key_capabilities')]
            else:
                ccapb = ""

            # check if capabilities OK
            if lcapb in ccapb:
                capbok = True
            else:
                capbok = False

            #print("usage: {} | ctype: {} | ccapb: {} | lcapb: {} | capbok: {}".format(usage,ctype,ccapb,lcapb,capbok))

            # check for main lines
            if ctype in main_lines and capbok and not correct_line:

                # we must be on the correct line
                #print("we are now on the correct line")
                correct_line = True
                current_line = ctype

                for x in mainparts.keys():
                    
                    # skip the type
                    if x == 'type':
                        continue

                    # add the other info to the tmpresult array
                    y = '{}_{}_{}'.format(usage, ctype, x)
                    if x == 'pubkey_algorithm':
                        p = pieces[mainparts.get(x)]
                        z = pubkeys.get(p) if p is not None else ''
                    else:
                        z = pieces[mainparts.get(x)]

                    tmpresult[y] = z

            # check for follow lines
            elif correct_line and ctype in follow_lines:

                for x in followparts.keys():

                    # skip the type
                    if x == 'type':
                        continue

                    # add the other info to the tmpresult array

                    y = '{}_{}_{}_{}'.format(usage, current_line, ctype, x)
                    if x == 'pubkey_algorithm':
                        p = pieces[followparts.get(x)]
                        z = pubkeys.get(p) if p is not None else ''
                    else:
                        z = pieces[followparts.get(x)]

                    tmpresult[y] = z

            # if not, we have reached a new key or the end
            else:
                #print("we are no longer on the correct line")
                correct_line = False

        msg.vvvv("renaming tmpresult keys; usage [{}]".format(usage))

        #
        # MAPPING
        #ssb_fpr_userid  sec_fpr_userid master_cert_sec_fingerprint
        keymap = {
            'regular'   : {
                'cert_sec_fpr_userid'       : 'master_cert_sec_fingerprint',
                'cert_sec_curve_name'       : 'master_cert_sec_keycurve',
                'cert_sec_grp_userid'       : 'master_cert_sec_keygrip',
                'cert_sec_key_length'       : 'master_cert_sec_keybits',
                'cert_sec_creationdate'     : 'master_cert_sec_creationdate',
                'cert_sec_keyid'            : 'master_cert_sec_keyid',
                'cert_sec_expirationdate'   : 'master_cert_sec_expirationdate',
                'sign_ssb_fpr_userid'       : 'subkey_sign_sec_fingerprint',
                'sign_ssb_curve_name'       : 'subkey_sign_sec_keycurve',
                'sign_ssb_grp_userid'       : 'subkey_sign_sec_keygrip',
                'sign_ssb_key_length'       : 'subkey_sign_sec_keybits',
                'sign_ssb_creationdate'     : 'subkey_sign_sec_creationdate',
                'sign_ssb_keyid'            : 'subkey_sign_sec_keyid',
                'sign_ssb_expirationdate'   : 'subkey_sign_sec_expirationdate',
                'encr_ssb_fpr_userid'       : 'subkey_encr_sec_fingerprint',
                'encr_ssb_curve_name'       : 'subkey_encr_sec_keycurve',
                'encr_ssb_grp_userid'       : 'subkey_encr_sec_keygrip',
                'encr_ssb_key_length'       : 'subkey_encr_sec_keybits',
                'encr_ssb_creationdate'     : 'subkey_encr_sec_creationdate',
                'encr_ssb_keyid'            : 'subkey_encr_sec_keyid',
                'encr_ssb_expirationdate'   : 'subkey_encr_sec_expirationdate',
                'auth_ssb_fpr_userid'       : 'subkey_auth_sec_fingerprint',
                'auth_ssb_curve_name'       : 'subkey_auth_sec_keycurve',
                'auth_ssb_grp_userid'       : 'subkey_auth_sec_keygrip',
                'auth_ssb_key_length'       : 'subkey_auth_sec_keybits',
                'auth_ssb_creationdate'     : 'subkey_auth_sec_creationdate',
                'auth_ssb_keyid'            : 'subkey_auth_sec_keyid',
                'auth_ssb_expirationdate'   : 'subkey_auth_sec_expirationdate',
            },
            'backup_sign'   : {
                'cert_sec_fpr_userid'       : 'sign_master_cert_sec_fingerprint',
                'cert_sec_curve_name'       : 'sign_master_cert_sec_keycurve',
                'cert_sec_grp_userid'       : 'sign_master_cert_sec_keygrip',
                'cert_sec_key_length'       : 'sign_master_cert_sec_keybits',
                'cert_sec_creationdate'     : 'sign_master_cert_sec_creationdate',
                'cert_sec_keyid'            : 'sign_master_cert_sec_keyid',
                'cert_sec_expirationdate'   : 'sign_master_cert_sec_expirationdate',
                'sign_ssb_fpr_userid'       : 'sign_subkey_sign_sec_fingerprint',
                'sign_ssb_curve_name'       : 'sign_subkey_sign_sec_keycurve',
                'sign_ssb_grp_userid'       : 'sign_subkey_sign_sec_keygrip',
                'sign_ssb_key_length'       : 'sign_subkey_sign_sec_keybits',
                'sign_ssb_creationdate'     : 'sign_subkey_sign_sec_creationdate',
                'sign_ssb_keyid'            : 'sign_subkey_sign_sec_keyid',
                'sign_ssb_expirationdate'   : 'sign_subkey_sign_sec_expirationdate',
            },
            'backup_encr'   : {
                'cert_sec_fpr_userid'       : 'encr_master_cert_sec_fingerprint',
                'cert_sec_curve_name'       : 'encr_master_cert_sec_keycurve',
                'cert_sec_grp_userid'       : 'encr_master_cert_sec_keygrip',
                'cert_sec_key_length'       : 'encr_master_cert_sec_keybits',
                'cert_sec_creationdate'     : 'encr_master_cert_sec_creationdate',
                'cert_sec_keyid'            : 'encr_master_cert_sec_keyid',
                'cert_sec_expirationdate'   : 'encr_master_cert_sec_expirationdate',
                'encr_ssb_fpr_userid'       : 'encr_subkey_encr_sec_fingerprint',
                'encr_ssb_curve_name'       : 'encr_subkey_encr_sec_keycurve',
                'encr_ssb_grp_userid'       : 'encr_subkey_encr_sec_keygrip',
                'encr_ssb_key_length'       : 'encr_subkey_encr_sec_keybits',
                'encr_ssb_creationdate'     : 'encr_subkey_encr_sec_creationdate',
                'encr_ssb_keyid'            : 'encr_subkey_encr_sec_keyid',
                'encr_ssb_expirationdate'   : 'encr_subkey_encr_sec_expirationdate',
            },
        }

        #
        # rename result keys / only use the relevant ones from the mapping
        #
        result = {}
        resultiterator = tmpresult.copy()
        km = keymap.get(mapping)
        for k,v in resultiterator.items():
            
            # only for keys which exist in the mapping dict
            if k in km:
                nk = km.get(k)
                result[nk] = tmpresult.pop(k)

        #
        # return results
        #
        return result
