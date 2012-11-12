#!/usr/bin/env python

import struct
import _winreg
import hmac

# requires pip install pbkdf2
from pbkdf2 import PBKDF2

# --------------------------------------------------------------------------------------
# ORIGINALLY FOUND IN pynt/helpers/crypt.py
# REIMPLEMENTED USING: http://sourceforge.net/projects/pywin32/files/pywin32/Build%20217/
import win32crypt

def unprotect_data(data_in, extra_entropy = None):    
    (desc, data_out) = win32crypt.CryptUnprotectData( data_in, extra_entropy, None, None, 0x01 )
    return data_out

# --------------------------------------------------------------------------------------
# FROM common_util/keystore/keystore_win32.py

class KeyStore(object):
    
    # KEY LOCATION:
    # (Windows) HKCU\Software\Dropbox\ks\Client REG_BINARY
    # (Linux) 'hostkeys' file (obfuscated)
    
    def get_versioned_key(self, name, hmac_keys):

        hkey = _winreg.OpenKey( _winreg.HKEY_CURRENT_USER, "SOFTWARE\\Dropbox\\ks" )

        # returns (data, type)
        hmaced_payload = _winreg.QueryValueEx( hkey, name )[0]

        # remove f***ing NULL byte (_winreg.QueryValueEx != Dropbox registry API ?!?)
        hmaced_payload = hmaced_payload[:-1]
        
        version, payload_len = struct.unpack_from('BL', hmaced_payload)
        hmac_size = len(hmaced_payload) - payload_len - 8
        v, l, payload, h = struct.unpack('BL%ds%ds' % (payload_len, hmac_size), hmaced_payload)
        
        try:
            hm_key = hmac_keys[v]
        except KeyError:
            raise KeychainMissingItem('Parsing error, bad version')

        hm = hmac.new(hm_key)
        if hm.digest_size != len(h):
            raise KeychainMissingItem('Bad digest size')

        hm.update(hmaced_payload[:-hm.digest_size])
        if hm.digest() != h:
            raise KeychainMissingItem('Bad digest')

        unprotected_payload = unprotect_data(payload, hm_key)

        return (v, unprotected_payload)

# --------------------------------------------------------------------------------------
# FROM core/mapreduce.py

class Version0(object):
    USER_HMAC_KEY = '\xd1\x14\xa5R\x12e_t\xbdw.7\xe6J\xee\x9b'
    APP_KEY = '\rc\x8c\t.\x8b\x82\xfcE(\x83\xf9_5[\x8e'
    APP_IV = '\xd8\x9bC\x1f\xb6\x1d\xde\x1a\xfd\xa4\xb7\xf9\xf4\xb8\r\x05'
    APP_ITER = 1066
    USER_KEYLEN = 16
    DB_KEYLEN = 16

    def get_database_key(self, user_key):
        return PBKDF2(passphrase=user_key, salt=self.APP_KEY, iterations=self.APP_ITER).read(self.DB_KEYLEN)

# --------------------------------------------------------------------------------------
# FROM core/mapreduce.py

class DBKeyStore(object):

    def __init__(self):
        self.parsers = {0: Version0()}
        self.hmac_keys = dict(((v, self.parsers[v].USER_HMAC_KEY) for v in self.parsers))
        self.ks = KeyStore()
        self.max_version = 0
        # simplified version
        # ...
        return
    
    def get_user_key(self):
        version, user_key = self.ks.get_versioned_key('Client', self.hmac_keys)
        # WARNING: original source displays dropbox_hash(user_key) instead
        # dropbox_hash() is defined in client_api/hashing.py
        print 'KEYSTORE: got user key (%d, %s)', version, repr(user_key)
        return (version, user_key)

    def KeychainAuthCanceled(self, version = 0):
        if version:
            raise Exception('invalid version number')
        version, user_key = self.get_user_key()
        return self.parsers[version].get_database_key(user_key)

# --------------------------------------------------------------------------------------
# main

import binascii

dbks = DBKeyStore()
# user_key is a tuple: (version,data)
user_key = dbks.get_user_key()
print "User key: ", binascii.hexlify( user_key[1] )

v0 = Version0()
db_key = v0.get_database_key(user_key[1])
print "Database key: ", binascii.hexlify( db_key )

