### EightFingers
Simple AES encrypt/decrypt module

### Usage
pure_key usage:<br/>
&nbsp;To Write down randomly generated key and store them in a safe place.<br/>  
```
    >>> from eightfingers import EightFingers as ef
    >>> encrypted = ef(pure_key=True).encrypt_secret('Wild Armonds')
    >>> encrypted
    {'auth_string': 't1T7 - RNZd - AXXP - Qw8d - BJE0 - BGQR - ORTP
        - TbBK - twkK - D6z4 - QqA=',
    'data': 'EDThlYAktM3zMNMrtjd2IvkuS/UYq1aXeQljsocB2s4='}

    >>> decrypted = ef(pure_key=True, auth_string=encrypted['auth_string']
                                ).decrypt_secret(encrypted['data'])
    >>> decrypted
    'Wild Armonds'
```

-----------------------------------------------------------------------------

hash_key usage:<br/>
&nbsp;To make password as you wish.<br/>
```
    >>> from eightfingers import EightFingers as ef
    >>> encrypted = ef('password').encrypt_secret('secret')
    >>> encrypted
    {'auth_string': 'c2hhMjU2JDEwMDAwMCRwX3MkVrdVMCnf5rtuyuAYppCo ...
                        ... ',
     'data': 'aVlzkns3yznKJvHXABJyUF94AfU05vWoQrOtAt/857o='}
    >>> decrypted = ef('password', auth_string=encrypted['auth_string']
                            ).decrypt_secret(encrypted['data'])
    >>> decrypted
    'secret'

    # optinos
    # use two key derivation function. (slow)
    >>> ef('password', m_kdf='scrypt', e_kdf='bcrypt') ... 

    # choose between scrypt and bcrypt
    >>> ef('password', m_kdf='bcrypt', e_kdf=None) ... 

    # default
    >>> ef('password', m_kdf='scrypt', e_kdf=None) ...
```

auth_string format:<br/>
&nbsp;   [salt] $s_ms$ [magic_string] $ks$ [encryption_salt]<br/>
&nbsp;   ---------------------------------------------------<br/>

Two Key derivation process:<br/>
&nbsp;Derive master key with [salt] and decrypt [magic_string][:magic_string_len]<br/> 
&nbsp;if decrypted [:magic_string_len] and [magic_string_len:] are identical, decrypt [encryption_salt]<br/>
&nbsp;Derive encryption key with decrypted [encryption_salt] for encrypting/decrypting secret.<br/>
    

### Dependency
bcrypt(https://pypi.org/project/bcrypt/)<br/>
&nbsp;   $ pip install bcrypt<br/>
pycryptodome(https://pypi.org/project/pycryptodome/)<br/>
&nbsp;   $ pip install pycryptodome<br/>
