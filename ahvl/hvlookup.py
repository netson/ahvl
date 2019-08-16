#
# import modules
#
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from time import gmtime, strftime
from ahvl.hashivault import HashiVault
from ahvl.generate.salt import GenerateSalt
from ahvl.generate.password import GeneratePassword
from ahvl.generate.sshkey import GenerateSSHKey
from ahvl.generate.sshhostkey import GenerateSSHHostKey
from ahvl.generate.gpgkey import GenerateGPGKey

#
# ansible display
#
display = Display()

#
# HvLookup
#
class HvLookup(LookupBase):

    #
    # initialize
    #
    def initialize(self, variables, **kwargs):

        # set vars/args
        self.variables = variables
        self.kwargs = kwargs

        # debug
        self.vv("using prefix [{}]".format(self.opts.prefix))
        self.vv("searching in [{}]".format(self.opts.get('fullpath')))
        self.vv("for key [{}]".format(self.opts.get('key')))
        if 'ret' in self.opts.getall().keys():
            self.vv("returning [{}]".format(self.opts.get('ret')))

        #
        # vault connect
        #
        self.connect(variables, **kwargs)

    #
    # vault connect
    #
    def connect(self, variables, **kwargs):

        # connect to vault and return client
        self.vv("connecting to vault")
        self.vault = HashiVault(variables, self, **kwargs)

    #
    # cleanup at end
    #
    def cleanup(self):

        self.vv("cleaning up after ourselves")

        # remove dir if it still exists;
        # it may have been deleted by a generate method already
        if self.opts.isdir(self.opts.get('ahvl_tmppath')):
            self.opts.delete_tmp_dir(self.opts.get('ahvl_tmppath'))

        # unset variables
        del self.opts
        del self.variables
        del self.kwargs
        del self.vault

    #
    # general method to find secret
    #
    def return_secret(self, secret_type, options):

        # find the correct secret
        funcname = "return_{}".format(secret_type)
        self.vv("searching secret using function [{}]".format(funcname))
        func = getattr(self, funcname)
        secret = func(options)

        # cleanup
        self.cleanup()

        # return secret
        result = []
        result.append(secret)
        return result

    #
    # return password
    #
    def return_password(self, options):

        # determine if we need to generate a secret or not
        if options.get('ret') == "onetime":
            secret = True
        else:
            secret = False

        # set value if it hasn't been set
        if not secret:
            secret = self.find_password(options)

        # sanity check
        if not secret:
            self.error("the value for [{}] could not be found for fullpath [{}]".format(options.get('key'), options.get('fullpath')))

        # get the correct out according to the config value
        funcname = "return_{}".format(options.get('ret'))
        self.vv("fetching return function [{}]".format(options.get('ret')))
        func = getattr(self, funcname)
        secret = func(secret)
        return secret

    #
    # return sshkey
    #
    def return_sshkey(self, options):

        # find value
        secret = self.find_sshkey(options)

        # sanity check
        if not secret:
            self.error("the value for [{}] could not be found for fullpath [{}]".format(options.get('key'), options.get('fullpath')))

        # return
        return secret

    #
    # return sshhostkey
    #
    def return_sshhostkey(self, options):

        # find value
        secret = self.find_sshhostkey(options)

        # sanity check
        if not secret:
            self.error("the value for [{}] could not be found for fullpath [{}]".format(options.get('fullkey'), options.get('fullpath')))

        # return
        return secret

    #
    # return gpgkey
    #
    def return_gpgkey(self, options):

        # find value
        secret = self.find_gpgkey(options)

        # sanity check
        if not secret:
            self.error("the value for [{}] could not be found for fullpath [{}]".format(options.get('key'), options.get('fullpath')))

        # return
        return secret

    #
    # return secret with hash function
    #
    def return_plaintext(self, secret):
        return secret

    def return_hexsha256(self, secret):
        from passlib.hash import hex_sha256
        return hex_sha256.hash(secret)

    def return_hexsha512(self, secret):
        from passlib.hash import hex_sha512
        return hex_sha512.hash(secret)

    def return_sha256crypt(self, secret):
        from passlib.hash import sha256_crypt
        return sha256_crypt.hash(secret, salt=self.find_salt(self.opts))

    def return_sha512crypt(self, secret):
        from passlib.hash import sha512_crypt
        return sha512_crypt.hash(secret, salt=self.find_salt(self.opts))

    def return_phpass(self, secret):
        from passlib.hash import phpass
        return phpass.hash(secret, salt=self.find_salt(self.opts))

    def return_mysql41(self, secret):
        from passlib.hash import mysql41
        return mysql41.hash(secret)

    def return_postgresmd5(self, secret):
        from passlib.hash import postgres_md5
        return postgres_md5.hash(secret, user=self.opts.get('key'))

    def return_onetime(self, secret):
        pwdgen = GeneratePassword(self.variables, self, **self.kwargs)
        return pwdgen.generate()

    #
    # find salt
    #
    def find_salt(self, options):

        # get salt key
        saltgen = GenerateSalt(self.variables, self, **self.kwargs)
        key = saltgen.get_key()

        # attempt to find salt
        if not options.get('renew'):
            self.vv("searching vault for [{}] in [{}]".format(key, options.get('fullpath')))
            salt = self.vault.get(options.get('fullpath'), key)
        else:
            self.vv("forcing new salt generation for [{}] in [{}]".format(key, options.get('fullpath')))
            salt = None

        # check for empty value
        if salt is None:

            self.vv("salt [{}] not found; generating".format(key))
            salt = saltgen.generate()

            # save salt to vault
            self.vault.set(
                fullpath=options.get('fullpath'),
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
            self.vv("searching vault for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
            secret = self.vault.get(options.get('fullpath'), options.get('key'))
        else:
            self.vv("forcing new password generation for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
            secret = None

        # check for empty secret
        if secret is None:

            self.vv("key [{}] not found; generating".format(options.get('key')))
            secretgen = GeneratePassword(self.variables, self, **self.kwargs)
            secret = secretgen.generate()

            # save generated secret
            self.vault.set(
                fullpath=options.get('fullpath'),
                key=options.get('key'),
                secret=secret,
            )

        return secret

    #
    # find sshkey
    #
    def find_sshkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            self.vv("searching vault for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
            secret = self.vault.get(options.get('fullpath'), options.get('key'))
            
            # sanity check
            # make sure the default sshkey has not been generated yet in the odd event where you
            # requested a key variant which was not initially generated for whatever reason
            if secret is None:
                self.vv("key not found, check if base key [private] exists")
                priv = self.vault.get(options.get('fullpath'), 'private')

                if priv is not None:
                    # if the key exists, fail due to existing key
                    self.error("It seems you have requested a key type [{}] which was not generated originally.\n"
                               "This could be the result of enabling options such as [sshkey_putty_enabled] or [sshkey_pkcs8_enabled],\n"
                               "or simply because you have requested a key type which could not be generated from the original keyfile.\n"
                               "For example, PKCS8 keys cannot be generated for Ed25519 keys".format(options.get('key')))

        else:
            self.vv("forcing new sshkey generation for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
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
                fullpath=options.get('fullpath'),
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
            self.vv("searching vault for [{}] in [{}]".format(options.get('fullkey'), options.get('fullpath')))
            secret = self.vault.get(options.get('fullpath'), options.get('fullkey'))
            
        else:
            self.vv("forcing new sshhostkey generation for [{}] in [{}]".format(options.get('fullkey'), options.get('fullpath')))
            secret = None

        # check for empty secret
        if secret is None:

            self.vv("hostkey [{}] not found; generating".format(options.get('fullkey')))

            secretgen   = GenerateSSHHostKey(self.variables, self, **self.kwargs)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                fullpath=options.get('fullpath'),
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
    # find sshhostkey
    #
    def find_gpgkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            self.vv("searching vault for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
            secret = self.vault.get(options.get('fullpath'), options.get('key'))
            
        else:
            self.vv("forcing new gpgkey generation for [{}] in [{}]".format(options.get('key'), options.get('fullpath')))
            secret = None

        # check for empty secret
        if secret is None:

            self.vv("gpgkey [{}] not found; generating".format(options.get('key')))

            # save original key
            key = self.opts.get('key')

            # get sign password
            options.set('key', "private_sign_password")
            pwd_sign = self.find_password(options)

            # get encrypt password
            options.set('key', "private_encrypt_password")
            pwd_encr = self.find_password(options)

            # reset key
            options.set('key', key)

            # generate gpgkey
            secretgen   = GenerateGPGKey(self.variables, self, gpgkey_password_sign=pwd_sign, gpgkey_password_encr=pwd_encr, **self.kwargs)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                fullpath=options.get('fullpath'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('key') not in secrets:
                self.error("the requested key [{}] could not be found after generating the gpgkey; "
                           "have you requested an invalid combination?".format(options.get('key')))

            # set proper return value
            secret = secrets[options.get('key')]

        return secret

    #
    # methods to use ansible's verbose debugging features with a timestamp
    #
    def d(self, msg):
        return "{}  {}".format(strftime("%Y-%m-%d %H:%M:%S", gmtime()), msg)

    def v(self, msg):
        display.v(self.d(msg))

    def vv(self, msg):
        display.vv(self.d(msg))

    def vvv(self, msg):
        display.vvv(self.d(msg))

    def debug(self, msg):
        display.debug(self.d(msg))

    def error(self, msg):
        msg = "\n\nHASHI_VAULT LOOKUP ERROR:\n{}".format(msg)
        raise AnsibleError(msg)
