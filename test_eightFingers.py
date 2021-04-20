# -*- encoding: utf-8 -*-
import unittest
from eightfingers import EightFingers

class TestBasic(unittest.TestCase):
    def setUp(self):
        self.ef = EightFingers()
        # random bytes(32)
        self.test_bytes = bytes(b"\xb1\xd3\x1aZ\x03\xd4=\xdb\x12cYF\x1f["
                    b"\xb4\x8d\x8ct\xf5SnF\xd1^a\x0b\x1e\xaca\xe6\xcc\x9f")
        # b64encoded of test-bytes
        self.test_str = 'sdMaWgPUPdsSY1lGH1u0jYx09VNuRtFeYQserGHmzJ8='
    
    def test_basic_encrypt_decrypt(self):
        # case 1 pure_key witout auth_string
        encrypted  = EightFingers(pure_key=True).encrypt_secret('Wild Armonds')
        decrypted = EightFingers(pure_key=True, auth_string=\
                encrypted['auth_string']).decrypt_secret(encrypted['data'])
        self.assertEqual('Wild Armonds', decrypted)

        # case 2 pure_key with specific key
        encrypted = EightFingers(pure_key=True, auth_string=self.test_str)\
                .encrypt_secret('Wild Armonds')
        decrypted = EightFingers(pure_key=True, auth_string=self.test_str)\
                .decrypt_secret(encrypted['data'])
        self.assertEqual('Wild Armonds', decrypted)

        # case 3 with key with KDF (m_key=scrypt, e_key=bcrypt)
        encrypted = EightFingers('password').encrypt_secret('Wild Armonds')
        decrypted = EightFingers('password', auth_string=encrypted['auth_string'])\
                .decrypt_secret(encrypted['data'])
        self.assertEqual('Wild Armonds', decrypted)

        # case 4 with key with KDF (m_key=secrypt)  
        encrypted = EightFingers('password', e_kdf=None)\
                .encrypt_secret('Wild Armonds')
        decrypted = EightFingers('password', auth_string=encrypted['auth_string'])\
                .decrypt_secret(encrypted['data'])
        self.assertEqual('Wild Armonds', decrypted)

        # case 5 with key with KDF (m_key=bcrypt)
        encrypted = EightFingers('password', m_kdf='bcrypt', e_kdf=None)\
                .encrypt_secret('Wild Armonds')
        decrypted = EightFingers('password', auth_string=encrypted['auth_string'])\
                .decrypt_secret(encrypted['data'])
        self.assertEqual('Wild Armonds', decrypted)
    
    def test_b64__coding(self):
        # case 1 bytes 
        self.assertIsInstance(self.ef._b64__coding(self.test_bytes), str)
        # case 2 str 
        self.assertIsInstance(self.ef._b64__coding(self.test_str), bytearray)
        # case 3 bytesarray
        self.assertIsInstance(self.ef._b64__coding(bytearray(self.test_bytes))
                , str)
        # equality bytes to string
        self.assertEqual(self.test_bytes, self.ef._b64__coding(self.test_str))
        
        # equlity str to bytes
        self.assertEqual(self.test_str, self.ef._b64__coding(self.test_bytes))
        
        # ignore human readable assistent sign ' - ' from str type
        test_human_readable = self.ef._bytes_to_human_readable(self.test_bytes)
        self.assertEqual(self.test_bytes, self.ef._b64__coding(
            test_human_readable))

    def test_bytes_to_human_readable(self):
        # case 1  (bytes len = 32)
        expected = '%s%s' % ('sdMa - WgPU - PdsS - Y1lG - H1u0',
                             ' - jYx0 - 9VNu - RtFe - YQse - rGHm - zJ8=')
        result = self.ef._bytes_to_human_readable(self.test_bytes) 
        self.assertEqual(expected, result)
        
        # case 2 (bytes len = 41)
        bytes_sample = bytearray(b"\x1f\xe1\x16\xdd\x10`\xfc\xa7\xca\xce\\\xa2\x8d"
                                 b"\xeb/Y\xfd\x82\x02J\xca\xd3C\xbc7\xfa'" 
                                 b"\xd4\xba\xc1\\\x1c\x0bkb\n\xe7\n?\xb0\xec")
        expected = '%s%s' % ('H+EW - 3RBg - /KfK - zlyi - jesv - Wf2C - ',
                'AkrK - 00O8 - N/on - 1LrB - XBwL - a2IK - 5wo/ - sOw=') 
        result = self.ef._bytes_to_human_readable(bytes_sample)
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
