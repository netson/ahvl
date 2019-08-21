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
from ahvl.options.lookup.credential import OptionsLookupCredential
from ahvl.options.hashivault import OptionsHashiVault

from ahvl.generate.salt import GenerateSalt
from ahvl.generate.password import GeneratePassword
from ahvl.generate.sshkey import GenerateSSHKey
from ahvl.generate.sshhostkey import GenerateSSHHostKey
from ahvl.generate.gpgkey import GenerateGPGKey

#
# message
#
msg = AhvlMsg()
hlp = AhvlHelper()

#
# AhvlLookup
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
                    "OptionsLookupCredential",
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
        self.opts.delete_tmp_dir()

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
        # explicitly checking for None instead of an empty value prevents error when the requested value is empty
        # this may be the case with, for example, the expiration date of a GPG key
        if secret is None:
            self.cleanup()
            msg.fail("the 'in' [{}] could not be found at path [{}]".format(options.get('in'), options.get('path')))

        # cleanup and return
        self.cleanup()
        return [secret]

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

    def return_pbkdf2sha256(self, secret, options):
        from passlib.hash import pbkdf2_sha256
        return pbkdf2_sha256.hash(secret, salt=bytes(self.find_salt(options)))

    def return_pbkdf2sha512(self, secret, options):
        from passlib.hash import pbkdf2_sha512
        return pbkdf2_sha512.hash(secret, salt=bytes(self.find_salt(options)), rounds=58000)

    def return_argon2(self, secret, options):
        from passlib.hash import argon2
        return argon2.using(salt=bytes(self.find_salt(options)), rounds=32).hash(secret)

    def return_grubpbkdf2sha512(self, secret, options):
        from passlib.hash import grub_pbkdf2_sha512
        return grub_pbkdf2_sha512.hash(secret, salt=bytes(self.find_salt(options)), rounds=38000)

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
            msg.vv("searching sshkey in vault for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('in'))

        else:
            msg.vv("forcing new sshkey generation for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = None

        # check for empty secret
        if secret is None and options.get('autogenerate'):

            msg.vv("sshkey [{}] not found; generating".format(options.get('in')))

            # save original key
            origin = options.get('in')

            # get master password
            options.set('in', 'password')
            pwd_master = self.find_password(options)

            # reset key
            options.set('in', origin)

            # generate gpgkey
            secretgen   = GenerateSSHKey(self, passphrase=pwd_master)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                path=options.get('path'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('in') not in secrets:
                msg.fail("the requested 'in' [{}] could not be found after generating the sshkey; "
                           "have you requested an invalid combination?".format(options.get('in')))

            # set proper return value
            secret = secrets[options.get('in')]

        # secret not found, but autogenerate is disabled
        elif secret is None:
            msg.fail("the requested 'in' [{}] could not be found and autogenerate is disabled; "
                           "please double check your settings and try again".format(options.get('in')))

        return secret


    #
    # find sshhostkey
    #
    def find_sshhostkey(self, options):

        # attempt to find secret
        if not options.get('renew'):
            msg.vv("searching sshhostkey in vault for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = self.vault.get(options.get('path'), options.get('in'))

        else:
            msg.vv("forcing new sshhostkey generation for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = None

        # check for empty secret
        if secret is None and options.get('autogenerate'):

            msg.vv("sshhostkey [{}] not found; generating".format(options.get('in')))

            # generate gpgkey
            secretgen   = GenerateSSHHostKey(self)
            secrets     = secretgen.generate()

            # save generated secrets
            self.vault.setdict(
                path=options.get('path'),
                secrets=secrets,
            )

            # get requested secret
            if options.get('in') not in secrets:
                msg.fail("the requested 'in' [{}] could not be found after generating the sshhostkey; "
                           "have you requested an invalid combination?".format(options.get('in')))

            # set proper return value
            secret = secrets[options.get('in')]

        # secret not found, but autogenerate is disabled
        elif secret is None:
            msg.fail("the requested 'in' [{}] could not be found and autogenerate is disabled; "
                           "please double check your settings and try again".format(options.get('in')))

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
            msg.vv("forcing new gpgkey generation for [{}] in [{}]".format(options.get('in'), options.get('path')))
            secret = None

        # check for empty secret
        if secret is None and options.get('autogenerate'):

            msg.vv("gpgkey [{}] not found; generating".format(options.get('in')))

            # save original key
            origin = options.get('in')

            # get master password
            if options.get('gpgkey_keyset') == 'backup':
                options.set('in', 'encr_master_cert_sec_password')
                pwd_master2 = self.find_password(options)
                options.set('in', 'sign_master_cert_sec_password')
            else:
                options.set('in', 'master_cert_sec_password')
                pwd_master2 = ''

            pwd_master = self.find_password(options)

            # reset key
            options.set('in', origin)

            # generate gpgkey
            secretgen   = GenerateGPGKey(self, passphrase=pwd_master, passphrase2=pwd_master2)
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


    #
    # find password
    #
    def find_credential(self, options):

        # attempt to find secret
        msg.vv("searching credential in vault for [{}] in [{}]".format(options.get('in'), options.get('path')))
        secret = self.vault.get(options.get('path'), options.get('in'))

        # check for empty secret
        if secret is None:

            # credentials are not automatically generated
            msg.fail("the requested credential [{}] could not be found at [{}]; auto generating credentials is not possible.".format(options.get('in'), options.get('path')))

        return secret
