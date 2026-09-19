# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2019 Albert Moky
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ==============================================================================

from typing import Optional, Union

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_PKCS1_v1_5

from dimp import final
from dimp import StrMap, MutableStrMap
from dimp import EncryptKey, DecryptKey
from dimp import PublicKey, PublicKeyFactory
from dimp import PrivateKey, PrivateKeyFactory
from dimp import TransportableData
from dimp import PlainData

from .algorithms import AsymmetricAlgorithms
from .keys import BaseKey, BasePublicKey, BasePrivateKey


class RSAPublicKey(BasePublicKey, EncryptKey):
    """ RSA Public Key

        keyInfo format: {
            algorithm  : "RSA",
            data       : "..." // base64_encode()
        }
    """

    def __init__(self, key: StrMap):
        super().__init__(key)
        # lazy load
        self.__key: Optional[RSA.RsaKey] = None
        self.__data: Optional[TransportableData] = None

    def key_size(self) -> int:
        """Get the RSA key size (bytes).

        The size is read from the 'keySize' field of the key info,
        default is 128 bytes (1024 bits).
        """
        # TODO: get from key
        return self.get_int(key='keySize') or 128  # 1024 / 8

    @property  # protected
    def rsa_key(self) -> RSA.RsaKey:
        """Get the native RSA public key object.

        The key data (PEM encoded) is decoded from the 'data' field.
        """
        verify_key = self.__key
        if verify_key is None:
            # data in 'PEM' format
            data = self.get_str(key='data') or ''
            verify_key = RSA.importKey(data)
            self.__key = verify_key
        return verify_key

    @property  # Override
    def data(self) -> TransportableData:
        ted = self.__data
        if ted is None:
            rsa_key = self.rsa_key
            assert rsa_key is not None, f'rsa key error: {self}'
            binary = rsa_key.exportKey(format='DER')
            ted = PlainData.create_with_bytes(binary=binary)
            self.__data = ted
        return ted

    # Override
    def encrypt(self, plaintext: bytes, extra: Optional[MutableStrMap] = None) -> bytes:
        """Encrypt `plaintext` with the public key (PKCS#1).

        Returns the ciphertext.
        """
        if len(plaintext) > self.key_size() - 11:
            raise ValueError(f'RSA plain text length error: {len(plaintext)}')
        cipher = Cipher_PKCS1_v1_5.new(self.rsa_key)
        return cipher.encrypt(plaintext)

    # Override
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify `signature` of `data` with the public key.

        Returns true if the signature is valid.
        """
        try:
            hash_obj = SHA256.SHA256Hash(data)
            verifier = Signature_PKCS1_v1_5.new(self.rsa_key)
            verifier.verify(hash_obj, signature)
            return True
        except ValueError:
            # raise ValueError("Invalid signature")
            return False


class RSAPrivateKey(BasePrivateKey, DecryptKey):
    """ RSA Private Key

        keyInfo format : {
            algorithm  : "RSA",
            data       : "..." // base64_encode()
        }
    """

    def __init__(self, key: StrMap):
        super().__init__(key)
        # lazy load
        self.__key: Optional[RSA.RsaKey] = None
        self.__data: Optional[TransportableData] = None
        self.__public_key: Optional[PublicKey] = None

    @classmethod
    def new_key(cls, bits: int = 1024) -> PrivateKey:
        """Generate a random RSA key pair.

        The key data contains the private key (PEM encoded, PKCS#1),
        with 'mode', 'padding' and 'digest' fields for the parameters.

        `bits` - key size in bits, default is 1024.

        Returns a new `RSAPrivateKey` instance.
        """
        rsa_key = RSA.generate(bits=bits)
        # store private key in PKCS#1 format
        pem = rsa_key.exportKey(format='PEM', pkcs=1).decode('utf-8')
        key = RSAPrivateKey(key={
            'algorithm': AsymmetricAlgorithms.RSA,
            'data': pem,
            'mode': 'ECB',
            'padding': 'PKCS1',
            'digest': 'SHA256',
        })
        key.__key = rsa_key
        # key.__data = PlainData.create(binary=rsa_key.exportKey(format='DER'))
        return key

    def key_size(self) -> int:
        """Get the RSA key size (bytes).

        The size is read from the 'keySize' field of the key info,
        default is 128 bytes (1024 bits).
        """
        # TODO: get from key
        return self.get_int(key='keySize') or 128  # 1024 / 8

    @property  # protected
    def rsa_key(self) -> RSA.RsaKey:
        """Get the native RSA private key object.

        The key data (PEM encoded) is decoded from the 'data' field.
        """
        if self.__key is None:
            # data in 'PEM' format
            data = self.get_str(key='data') or ''
            tag1 = '-----BEGIN RSA PRIVATE KEY-----'
            tag2 = '-----END RSA PRIVATE KEY-----'
            pos2 = data.rfind(tag2)
            if pos2 > 0:
                pos1 = data.find(tag1)
                data = data[pos1: pos2 + len(tag2)]
            self.__key = RSA.importKey(data)
        return self.__key

    @property  # Override
    def data(self) -> TransportableData:
        ted = self.__data
        if ted is None:
            rsa_key = self.rsa_key
            assert rsa_key is not None, f'rsa key error: {self}'
            binary = rsa_key.exportKey(format='DER')
            ted = PlainData.create_with_bytes(binary=binary)
            self.__data = ted
        return ted

    @property  # Override
    def public_key(self) -> Union[PublicKey, EncryptKey]:
        """Calculate RSA public key from the private key.

        The public key is derived from the native RSA private key object
        and encoded to PEM format (PKCS#1).
        """
        pub = self.__public_key
        if pub is None:
            rsa_key = self.rsa_key
            pub_key = rsa_key.publickey()
            pem = pub_key.exportKey(format='PEM', pkcs=1).decode('utf-8')
            info = {
                'algorithm': AsymmetricAlgorithms.RSA,
                'data': pem,
                'mode': 'ECB',
                'padding': 'PKCS1',
                'digest': 'SHA256',
            }
            pub = RSAPublicKey(key=info)
            pub.__key = pub_key
            # pub.__data = PlainData.create_with_bytes(binary=pub_key.exportKey(format='DER'))
            self.__public_key = pub
        return pub

    # Override
    def decrypt(self, ciphertext: bytes, params: Optional[StrMap] = None) -> Optional[bytes]:
        """Decrypt `ciphertext` with the private key (PKCS#1).

        Returns the plaintext.
        """
        if len(ciphertext) != self.key_size():
            raise ValueError(f'RSA cipher text length error: {len(ciphertext)}')
        sentinel: Optional[bytes] = None
        try:
            cipher = Cipher_PKCS1_v1_5.new(self.rsa_key)
            return cipher.decrypt(ciphertext, sentinel)
        except ValueError:
            return None

    # Override
    def sign(self, data: bytes) -> bytes:
        """Sign `data` with the private key.

        Returns the signature.
        """
        hash_obj = SHA256.SHA256Hash(data)
        signer = Signature_PKCS1_v1_5.new(self.rsa_key)
        return signer.sign(hash_obj)

    # Override
    def match_encrypt_key(self, key: EncryptKey) -> bool:
        return BaseKey.match_encrypt_key(encrypt_key=key, decrypt_key=self)


"""
    Key Factories
    ~~~~~~~~~~~~~
"""


@final
class RSAPublicKeyFactory(PublicKeyFactory):
    """RSA Public Key Factory

    Parses a dictionary into an `RSAPublicKey` instance.
    """

    # Override
    def parse_public_key(self, key: StrMap) -> Optional[PublicKey]:
        # check 'data', 'algorithm'
        if key.get('data') is None or key.get('algorithm') is None:
            # key.data should not be empty
            # key.algorithm should not be empty
            return None
        # OK
        return RSAPublicKey(key)


@final
class RSAPrivateKeyFactory(PrivateKeyFactory):
    """RSA Private Key Factory

    Generates a new `RSAPrivateKey` or parses a dictionary
    into an `RSAPrivateKey` instance.
    """

    # Override
    def generate_private_key(self) -> Optional[PrivateKey]:
        return RSAPrivateKey.new_key()

    # Override
    def parse_private_key(self, key: StrMap) -> Optional[PrivateKey]:
        # check 'data', 'algorithm'
        if key.get('data') is None or key.get('algorithm') is None:
            # key.data should not be empty
            # key.algorithm should not be empty
            return None
        # OK
        return RSAPrivateKey(key)
