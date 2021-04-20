#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
########################################################################
# eightfingers.py: simple AES encrypt/decrypt module.
#
# Copyright (C) 2020 Mima SJ Kang <gx_339-4@pm.me>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

###########################################################################
# eightfingers usage:
#   from eightfingers import EightFingers
#   
#   encrypted = EightFingers(pure_key=True).encrypt_secret('secret')
#   decrypted = EightFingers(pure_key=True, auth_string=encrypted['auth_string']
#                                   ).decrypt_secret(encrypted['data'])
#   
#   encrypted = EightFingers('password').encrypt_secret('secret')  
#   decrypted = EightFingers('password', auth_string=encrypted_hash['auth_string']
#                                   ).decrypt_secret(encrypted_hash['data']) 
#
###########################################################################

__version__ = "0.1"


import os
from hmac import compare_digest 
from base64 import b64encode, b64decode

import bcrypt
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad


class EightFingers:
    """ Simple data encrypt/decrypt moudle """
    MAX_PW_LEN = 72
    AES_BLOCK_SIZE = 16
    MAGIC_STRING_LEN = 30
    ENCODING = 'utf-8'
    KDF_LIST = ['scrypt', 'brypt']
    
    def __init__(self, passphrase=None, pure_key=False, auth_string=None,
                 m_kdf='scrypt', e_kdf=None):
        self.__pure = pure_key
        self._m_kdf = m_kdf
        self._e_kdf = e_kdf
        self._set_up(passphrase, auth_string)

    def new_auth_string(self, str_type=True):
        """ return string type auth_string """
        if self.__pure:
            auth_key = bytearray(os.urandom(32))
            auth_string = (self._bytes_to_human_readable(auth_key)
                    if str_type else auth_key)
        else:
            salt, auth_key = self._derive_key()
            magic_string = os.urandom(self.MAGIC_STRING_LEN)
            
            if self._e_kdf is None:
                auth_key = bytearray(b'%b$s_ms$%b%b$ks$%b' %
                        (salt, magic_string, self._encrypt(magic_string, auth_key),
                        b'n'))
            else:
                # generate salt for e_key
                if self._e_kdf == 'bcrypt':
                    e_key_salt = bytearray(bcrypt.gensalt())
                elif self._e_kdf == 'scrypt':
                    e_key_salt = bytearray(b'$sc$' + os.urandom(32))
                
                # auth_string foramt:
                #   [salt] $s_ms$ [magic_string] $ks$ [encryption_salt]
                auth_key = bytearray(b'%b$s_ms$%b%b$ks$%b' %
                        (salt, magic_string, self._encrypt(magic_string, auth_key),
                         self._encrypt(e_key_salt, auth_key)))
           
            auth_string = (self._b64__coding(auth_key) if str_type else auth_key)

        # clean up
        auth_key = bytearray(len(auth_key))
        del auth_key
        return auth_string

    def encrypt_secret(self, secret):
        """if auth_string is not given make new auth_string and
            return them as python dict({"auth_string": ..., "data": ...}) """
        # If auth_string is not given generate new auth_string.
        if self.__auth_string is None:
            is_new_key = True
            self.__auth_string = self.new_auth_string(str_type=False)
        else:
            is_new_key = False

        # get key from auth_string
        if self.__pure:
            key = self.__auth_string
        else:
            _, key = self._derive_key(hash_data=self._check_magic_string())

        # encrypt data
        e_secret = self._b64__coding(self._encrypt(secret.encode(
            self.ENCODING), key))
        # clean up
        key = bytearray(len(key))
        del key

        if is_new_key:
            auth_str = (self._bytes_to_human_readable(self.__auth_string)
                    if self.__pure else self._b64__coding(self.__auth_string))
            return {'auth_string': auth_str, 'data': e_secret}
        else:
            return {'data': e_secret}
            n, r, p = 2**20, 8, 1 


    def decrypt_secret(self, ciphertest):
        "Decrypt ciphertest(encrypted)"
        if self.__auth_string is None:
            raise SystemExit("Please specify auth_string")

        # get key from auth_string
        if self.__pure:
            key = self.__auth_string
        else:
            _, key = self._derive_key(hash_data=self._check_magic_string())

        # decrypt data
        d_secret = self._decrypt(self._b64__coding(ciphertest), key)

        # clean up
        key = bytearray(len(key))
        del key
        return d_secret.decode(self.ENCODING)

    def _derive_key(self, hash_data=None):
        if self.__pw is None:
            raise SystemExit("passphrase is missing")
        
        if hash_data is None:
            # derive new key.
            if self._m_kdf.startswith('scrypt'):
                return self._derive_scrypt()
            elif self._m_kdf.startswith('bcrypt'):
                return self._derive_bcrypt()
            else:
                raise ValueError("cannot implemente %s KDF." % self._m_kdf)
        else:
            if hash_data.startswith(b'$sc$'):
                return self._derive_scrypt(hash_data)
            elif hash_data.startswith(b'$2b$'):
                return self._derive_bcrypt(hash_data)
            else:
                raise ValueError("Can not support this salt data")

    def _derive_scrypt(self, hash_data=None):
        if hash_data is None:
            hash_data = b'$sc$' + os.urandom(32)
        
        _, salt = hash_data.split(b'$sc$')
        return hash_data, scrypt(self.__pw, salt, 32, N=2**20, r=8, p=1)

    def _derive_bcrypt(self, salt=None):
        if salt is None:
            salt = bcrypt.gensalt()
        d_key = bcrypt.kdf(password=b'password', salt=bytes(salt),
                            desired_key_bytes=32, rounds=100)
        return salt, d_key 
    
    def _check_magic_string(self):
        salt_and_ms, e_salt = self.__auth_string.split(b'$ks$')
        salt, magic_string = salt_and_ms.split(b'$s_ms$')
        
        # get key to decrypt magic_stirng
        _, key = self._derive_key(hash_data=salt)
       
       # decrypt magic string with deriven key
        decrypted_ms = self._decrypt(magic_string[self.MAGIC_STRING_LEN:], key)
        # compare magic_string
        if compare_digest(magic_string[:self.MAGIC_STRING_LEN], decrypted_ms):
            return salt if e_salt == b'n' else self._decrypt(e_salt, key) 
        else:
            raise SystemExit('[!] Password is not mached.')

    def _encrypt(self, secret, key):
        iv = os.urandom(self.AES_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(secret, self.AES_BLOCK_SIZE))
        # clean up
        key = bytearray(len(key))
        del key, secret
        return iv+encrypted

    def _decrypt(self, e_secret, key):
        try:
            cipher = AES.new(key, AES.MODE_CBC, e_secret[:self.AES_BLOCK_SIZE])
            data = unpad(cipher.decrypt(e_secret[self.AES_BLOCK_SIZE:]),
                         self.AES_BLOCK_SIZE)
        except ValueError:
            raise SystemExit('[!] Invalid Password') from None
        # clean up
        key = bytearray(len(key))
        del key
        return data

    def _b64__coding(self, value):
        if isinstance(value, str):
            value.replace(' - ', '')    # ignore meaningless sign
            return bytearray(b64decode(value.encode(self.ENCODING)))
        elif isinstance(value, bytearray) or isinstance(value, bytes):
            # If bytes type is given, return string type object.
            return b64encode(value).decode(self.ENCODING)
        else:
            return value
    
    def _bytes_to_human_readable(self, byte_obj):
        """ return b64 encoded human redable string of 32 size of bytes  """
        return ' - '.join([self._b64__coding(byte_obj)[i:i+4]
                           for i in range(0, len(b64encode(byte_obj)), 4)])

    def _set_up(self, passphrase, auth_string):
        # passphrase must be bytearray
        if passphrase is not None:
            if len(passphrase) > self.MAX_PW_LEN:
                raise ValueError('Too long passpharase')
            if isinstance(passphrase, bytearray):
                pw = passphrase
            elif isinstance(passphrase, str):
                pw = bytearray(passphrase, self.ENCODING)
            elif isinstance(passphrase, bytes):
                pw = bytearray(passphrase)
            else:
                raise TypeError('passphrase must be string or bytes')
        else:
            pw = None

        # if auth_string is given convert type to bytesarray
        if auth_string is not None:
            auth_string = self._b64__coding(auth_string)
        
        self.__pw = pw
        self.__auth_string = auth_string
        del pw, auth_string

    def __del__(self):
        if self.__auth_string is not None:
            self.__auth_string = bytearray(len(self.__auth_string))
            del self.__auth_string
        if self.__pw is not None:
            self.__pw = bytearray(len(self.__pw))
            del self.__pw
