#
# import modules
#
from ansible.plugins.lookup import LookupBase
from ahvl.helper import AhvlMsg, AhvlHelper
from ahvl.hashivault import HashiVault
from ahvl.options.lookup.password import OptionsLookupPassword
from ahvl.options.lookup.sshkey import OptionsLookupSSHKey
from ahvl.options.lookup.sshhostkey import OptionsLookupSSHHostKey
from ahvl.options.lookup.gpgkey import OptionsLookupGPGKey
from ahvl.options.hashivault import OptionsHashiVault
from ahvl.generate.salt import GenerateSalt
from ahvl.generate.password import GeneratePassword
from ahvl.generate.gpgkey import GenerateGPGKey

#
# message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# HvLookup
#
class AhvlLookup(LookupBase):

    #
    # initialize
    #
    def initialize(self, variables, **kwargs):

        # set vars/args
        msg.vvv("setting variables [{}] and kwargs [{}] on lookup module [{}]".format(len(variables), len(kwargs), self.__class__.__name__))
        self.variables = variables
        self.kwargs = kwargs

        #
        # vault connect
        #
        self.connect()

    #
    # vault connect
    #
    def connect(self):

        # connect to vault and return client
        msg.vv("initializing vault connection")
        self.vault = HashiVault()
        hvopts = OptionsHashiVault(self)
        self.vault.setopts(hvopts)
        self.vault.connect(self)
        msg.vv("vault connection established")

    #
    # set class options
    #
    def setopts(self, lookup_type):

        # determine object name
        accepted = ["OptionsLookupPassword",
                    "OptionsLookupSSHKey",
                    "OptionsLookupSSHHostKey",
                    "OptionsLookupGPGKey",
                    ]

        # sanity checkjohndoe34
        if lookup_type not in accepted:
            msg.fail("unexpected classname; [{}] given, but expected one of {}".format(lookup_type, accepted))

        # load options
        msg.vvv("loading options class [{}]".format(lookup_type))
        self.opts = eval(lookup_type)(self)

        # debug
        msg.v("using prefix [{}]".format(self.opts.prefix))
        msg.v("searching in [{}]".format(self.opts.get('path')))
        msg.v("finding 'find' [{}]".format(self.opts.get('find')))
        msg.v("for 'in' [{}]".format(self.opts.get('in')))
        msg.v("returning 'out' [{}]".format(self.opts.get('out')))

    #
    # cleanup at end
    #
    def cleanup(self):

        msg.vv("cleaning up after ourselves")

        # remove dir if it still exists;
        # it may have been deleted by a generate method already
        #self.opts.delete_tmp_dir()

        # unset variables
        del self.opts
        del self.variables
        del self.kwargs
        del self.vault

    #
    # general method to find secret
    #
    def return_secret(self, secret_type, options):

        # find the secret with the proper search method
        find = "find_{}".format(secret_type)
        msg.vv("searching secret using function [{}]".format(find))
        func = getattr(self, find)
        secret = func(options)

        # get the correct out according to the config value
        out = "return_{}".format(options.get('out'))
        msg.vv("fetching return function [{}]".format(options.get('out')))
        func = getattr(self, out)
        secret = func(secret, options)

        # sanity check
        if not secret:
            self.cleanup()
            msg.fail("the 'in' [{}] could not be found at path [{}]".format(options.get('in'), options.get('path')))

        # cleanup and return
        self.cleanup()
        return [secret]

    #
    # general method to find secret
    #
#    def return_secret_old(self, secret_type, options):
#
#        # find the correct secret
#        funcname = "return_{}".format(secret_type)
#        msg.vv("searching secret using function [{}]".format(funcname))
#        func = getattr(self, funcname)
#        secret = func(options)
#
#        # cleanup
#        self.cleanup()
#
#        # return secret
#        result = []
#        result.append(secret)
#        return result

    #
    # return password
    #
#    def return_password(self, options):
#
#        # determine if we need to generate a secret or not
#        if options.get('ret') == "onetime":
#            secret = True
#        else:
#            secret = False
#
#        # set value if it hasn't been set
#        if not secret:
#            secret = self.find_password(options)
#
#        # sanity check
#        if not secret:
#            msg.fail("the value for [{}] could not be found for path [{}]".format(options.get('key'), options.get('path')))
#
#        # get the correct out according to the config value
#        funcname = "return_{}".format(options.get('ret'))
#        msg.vv("fetching return function [{}]".format(options.get('ret')))
#        func = getattr(self, funcname)
#        secret = func(secret)
#        return secret

#    #
#    # return sshkey
#    #
#    def return_sshkey(self, options):
#
#        # find value
#        secret = self.find_sshkey(options)
#
#        # sanity check
#        if not secret:
#            msg.fail("the value for [{}] could not be found for path [{}]".format(options.get('key'), options.get('path')))
#
#        # return
#        return secret

#    #
#    # return sshhostkey
#    #
#    def return_sshhostkey(self, options):
#
#        # find value
#        secret = self.find_sshhostkey(options)
#
#        # sanity check
#        if not secret:
#            msg.fail("the value for [{}] could not be found for path [{}]".format(options.get('fullkey'), options.get('path')))
#
#        # return
#        return secret

#    #
#    # return gpgkey
#    #
#    def return_gpgkey(self, options):
#
#        # find value
#        secret = self.find_gpgkey(options)
#
#        # sanity check
#        if not secret:
#            msg.fail("the value for 'in' [{}] could not be found for path [{}]".format(options.get('in'), options.get('path')))
#
#        # return
#        return secret


    #
    # return secret with hash function
    #
    def return_plaintext(self, secret, options):
        return secret

    def return_hexsha256(self, secret, options):
        from passlib.hash import hex_sha256
        return hex_sha256.hash(secret)

    def return_hexsha512(self, secret, options):
        from passlib.hash import hex_sha512
        return hex_sha512.hash(secret)

    def return_sha256crypt(self, secret, options):
        from passlib.hash import sha256_crypt
        return sha256_crypt.hash(secret, salt=self.find_salt(options))

    def return_sha512crypt(self, secret, options):
        from passlib.hash import sha512_crypt
        return sha512_crypt.hash(secret, salt=self.find_salt(options))

    def return_phpass(self, secret, options):
        from passlib.hash import phpass
        return phpass.hash(secret, salt=self.find_salt(options))

    def return_mysql41(self, secret, options):
        from passlib.hash import mysql41
        return mysql41.hash(secret)

    def return_postgresmd5(self, secret, options):
        from passlib.hash import postgres_md5
        return postgres_md5.hash(secret, user=options.get('in'))

    #
    # find salt
    #
    def find_salt(self, options):

        # get salt key
        saltgen = GenerateSalt(self)
        key = saltgen.get_key()

        # attempt to find salt
        if not options.get('renew'):
            msg.vv("searching vault for [{}] in [{}]".format(key, options.get('path')))
            salt = self.vault.get(options.get('path'), key)
        else:
            msg.vv("forcing new salt generation for [{}] in [{}]".format(key, options.get('path')))
            salt = None

        # check for empty value
        if salt is None:

            msg.vv("salt [{}] not found; generating".format(key))
            salt = saltgen.generate()

            # save salt to vault
            self.vault.set(
                path=options.get('path'),
                key=key,
                secret=salt,
            )

        # return salt
        return salt
        
    #
    # find password
    #
    def find_password(self, options):

        # attempt to find secret
        if not options.get('renew'):
            msg.vv("searching password in vault for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('in'))
        else:
            msg.vv("forcing new password generation for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = None


        # check for empty secret
        if secret is None and options.get('autogenerate'):

            msg.vv("password [{}] not found; generating".format(options.get('in')))
            secretgen = GeneratePassword(self)
            secret = secretgen.generate()

            # save generated secret
            self.vault.set(
                path=options.get('path'),
                key=options.get('in'),
                secret=secret,
            )

        return secret

    #
    # find sshkey
    #
    def find_sshkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            msg.vv("searching vault for [{}] in [{}]".format(options.get('key'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('key'))
            
            # sanity check
            # make sure the default sshkey has not been generated yet in the odd event where you
            # requested a key variant which was not initially generated for whatever reason
            if secret is None:
                self.vv("key not found, check if base key [private] exists")
                priv = self.vault.get(options.get('path'), 'private')

                if priv is not None:
                    # if the key exists, fail due to existing key
                    self.error("It seems you have requested a key type [{}] which was not generated originally.\n"
                               "This could be the result of enabling options such as [sshkey_putty_enabled] or [sshkey_pkcs8_enabled],\n"
                               "or simply because you have requested a key type which could not be generated from the original keyfile.\n"
                               "For example, PKCS8 keys cannot be generated for Ed25519 keys".format(options.get('key')))

        else:
            msg.vv("forcing new sshkey generation for [{}] in [{}]".format(options.get('key'), options.get('path')))
            secret = None

        # check for empty secret
        if secret is None:

            self.vv("key [{}] not found; generating".format(options.get('key')))

            #pwdgen      = GeneratePassword(self.variables, self, **self.kwargs)
            #pwd         = pwdgen.generate()
            pwd         = self.find_password(options)
            secretgen   = GenerateSSHKey(self.variables, self, key_password=pwd, **self.kwargs)
            secrets     = secretgen.generate()

            # add generated password to secrets
            secrets['password'] = pwd

            # save generated secrets
            self.vault.setdict(
                path=options.get('path'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('key') not in secrets:
                self.error("the requested key [{}] could not be found after generating the sshkey; "
                           "have you requested an invalid combination?".format(options.get('key')))

            # set proper return value
            secret = secrets[options.get('key')]

        return secret

    #
    # find sshhostkey
    #
    def find_sshhostkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            self.vv("searching vault for [{}] in [{}]".format(options.get('fullkey'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('fullkey'))
            
        else:
            self.vv("forcing new sshhostkey generation for [{}] in [{}]".format(options.get('fullkey'), options.get('path')))
            secret = None

        # check for empty secret
        if secret is None:

            self.vv("hostkey [{}] not found; generating".format(options.get('fullkey')))

            secretgen   = GenerateSSHHostKey(self.variables, self, **self.kwargs)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                path=options.get('path'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('fullkey') not in secrets:
                self.error("the requested key [{}] could not be found after generating the sshhostkey; "
                           "have you requested an invalid combination?".format(options.get('fullkey')))

            # set proper return value
            secret = secrets[options.get('fullkey')]

        return secret

    #
    # find gpgkey
    #
    def find_gpgkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            msg.vv("searching gpgkey in vault for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('in'))

        else:
            msg.vv("forcing new gpgkey generation for [{}] in [{}]".format(options.get('in'), options.get('full')))
            secret = None

        # check for empty secret
        if secret is None and options.get('autogenerate'):

            msg.vv("gpgkey [{}] not found; generating".format(options.get('in')))

            # save original key
            origin = options.get('in')

            # get master password
            options.set('in', "master_sec_password")
            pwd_master = self.find_password(options)

            # reset key
            options.set('in', origin)

            # generate gpgkey
            secretgen   = GenerateGPGKey(self, passphrase=pwd_master)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                path=options.get('path'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('in') not in secrets:
                msg.fail("the requested 'in' [{}] could not be found after generating the gpgkey; "
                           "have you requested an invalid combination?".format(options.get('in')))

            # set proper return value
            secret = secrets[options.get('in')]

        # secret not found, but autogenerate is disabled
        elif secret is None:
            msg.fail("the requested 'in' [{}] could not be found and autogenerate is disabled; "
                           "please double check your settings and try again".format(options.get('in')))

        return secret

