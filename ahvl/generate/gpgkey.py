#
# import modules
#
from ahvl.options.generategpgkey import OptionsGenerateGPGKey
from ahvl.process import Process
from ansible.utils.display import Display
import gnupg
import os

#
# ansible display
#
display = Display()

#
# GenerateGPGKey
#
class GenerateGPGKey:

    def __init__(self, variables, lookup_plugin=None, **kwargs):

        #
        # options
        #
        self.opts = OptionsGenerateGPGKey(variables, lookup_plugin, **kwargs)

    # generate gpg keyfiles
    def generate(self):

        # get common info for keys
        title    = self.opts.get('gpgkey_name')
        username = self.opts.get('gpgkey_email')
        keytype  = self.opts.get('gpgkey_type')
        keybits  = self.opts.get('gpgkey_length')
        hostname = self.opts.get('gpgkey_hostname')
        expires  = self.opts.get('gpgkey_expiration')
        pref     = self.opts.get('gpgkey_pref')
        pwd_sign = self.opts.get('gpgkey_password_sign')
        pwd_encr = self.opts.get('gpgkey_password_encr')

        # determine keyring/secring
        homedir = self.opts.get_tmp_dir()
        tmpfile = self.opts.get_tmp_filename(False)
        keyring = "key_{}.gpg".format(tmpfile)
        secring = "sec_{}.gpg".format(tmpfile)

        # debug
        display.vvv("gpg homedir: {}".format(homedir))
        display.vvv("gpg keyring: {}".format(keyring))
        display.vvv("gpg secring: {}".format(secring))

        # init gpg
        gpg = gnupg.GPG(homedir=homedir, keyring=keyring, secring=secring)

        # generate keys
        display.vvv("generating sign key")
        sign_key = self.gen_gpgkey_default(gpg, "[sign]", keytype, keybits, title, username, hostname, pwd_sign, expires, pref)
        display.vvv("generating encrypt key")
        encr_key = self.gen_gpgkey_default(gpg, "[encryption]", keytype, keybits, title, username, hostname, pwd_encr, expires, pref)

        # set fingerprints
        display.vvv("getting sign key fingerprints")
        sign_fpr = sign_key.fingerprint
        display.vvv("getting encrypt key fingerprints")
        encr_fpr = encr_key.fingerprint

        # sign encryption key with sign key
        display.vvv("signing encryption key with sign key")
        gpg.sign_key(encr_fpr, default_key=sign_fpr, passphrase=pwd_sign)

        # get keys
        display.vvv("getting public key")
        encr_pubk = gpg.export_keys(encr_fpr)
        display.vvv("getting private key")
        encr_seck = gpg.export_keys(encr_fpr, secret=True, subkeys=True)

        # get key meta
        display.vvv("getting sign key meta")
        sign_meta = gpg.list_sigs(sign_fpr)[0] # contains only 1 item
        display.vvv("getting encrypt key meta")
        encr_meta = gpg.list_sigs(encr_fpr)[0] # contains only 1 item

        # set results
        result = {}
        result['private_encrypt'] = gpg.export_keys(encr_fpr, secret=True, subkeys=True)
        result['private_encrypt_password'] = pwd_encr
        result['private_encrypt_keyid'] = encr_meta['keyid']
        result['private_encrypt_fingerprint'] = encr_fpr
        result['private_encrypt_createddate'] = encr_meta['date']
        result['private_encrypt_expirydate'] = encr_meta['expires'] or "never"
        result['private_sign'] = gpg.export_keys(sign_fpr, secret=True, subkeys=True)
        result['private_sign_password'] = pwd_sign
        result['private_sign_keyid'] = sign_meta['keyid']
        result['private_sign_fingerprint'] = sign_fpr
        result['private_sign_createddate'] = sign_meta['date']
        result['private_sign_expirydate'] = sign_meta['expires'] or "never"
        result['public_encrypt'] = gpg.export_keys(encr_fpr)
        result['public_encrypt_keyid'] = encr_meta['keyid']
        result['public_encrypt_fingerprint'] = encr_fpr
        result['public_encrypt_createddate'] = encr_meta['date']
        result['public_encrypt_expirydate'] = encr_meta['expires'] or "never"
        result['public_sign'] = gpg.export_keys(sign_fpr)
        result['public_sign_keyid'] = sign_meta['keyid']
        result['public_sign_fingerprint'] = sign_fpr
        result['public_sign_createddate'] = sign_meta['date']
        result['public_sign_expirydate'] = sign_meta['expires'] or "never"

        # delete temp keys
        os.remove(os.path.join(homedir, keyring))
        os.remove(os.path.join(homedir, secring))
        os.remove(os.path.join(homedir, "{}~".format(keyring)))
        os.remove(os.path.join(homedir, "random_seed"))
        os.remove(os.path.join(homedir, "trustdb.gpg"))

        # return
        return result

    # generate keyfile
    def gen_gpgkey_default(self, gpg, sigenc, keytype, keylength, title, username, hostname, password, expires, preferences):

        # set input
        args = {'name_real': "{} {}".format(username, sigenc),
                'name_email': title,
                'name_comment': hostname,
                'expire_date': expires,
                'key_type': keytype.upper(),
                'key_length': int(keylength),
                'key_usage': 'encrypt,sign,auth', # not implemented
                'subkey_type': keytype.upper(),
                'subkey_length': int(keylength),
                'passphrase': password,
                'preferences': preferences}

        # generate key
        inp = gpg.gen_key_input(**args)
        key = gpg.gen_key(inp)
        fpr = key.fingerprint

        # return key object
        return key

    # function to cleanup
    def cleanup(self, tempfile, filename, sshkeys, filenames):

        # delete tmp files
        self.opts.delete_tmp_files(tempfile, filenames)

        # remove tmpdir
        self.opts.delete_tmp_dir(os.path.dirname(tempfile))
