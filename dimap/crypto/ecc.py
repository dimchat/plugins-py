# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2020 Albert Moky
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

import hashlib
from typing import Optional, Union

import ecdsa

from dimp import final
from dimp import StrMap
from dimp import PublicKey, PublicKeyFactory
from dimp import PrivateKey, PrivateKeyFactory
from dimp import TransportableData
from dimp import PlainData

from .algorithms import AsymmetricAlgorithms
from .keys import BasePublicKey, BasePrivateKey


class ECCPublicKey(BasePublicKey):
    """ ECC Public Key

        keyInfo format: {
            algorithm  : "ECC",
            curve      : "secp256k1",
            data       : "...", // base64_encode(),
            compressed : 0
        }
    """

    def __init__(self, key: StrMap):
        super().__init__(key)
        # lazy load
        self.__key: Optional[ecdsa.VerifyingKey] = None
        self.__data: Optional[TransportableData] = None

    @property
    def curve(self):
        return ecdsa.SECP256k1

    @property
    def hash_func(self):
        return hashlib.sha256

    @property
    def sig_decode(self):
        return ecdsa.util.sigdecode_der

    @property  # protected
    def ecc_key(self) -> ecdsa.VerifyingKey:
        """ Get the native ECC public key object (decoded from 'data') """
        verify_key = self.__key
        if verify_key is None:
            # data in 'PEM' format
            pem = self.get_str(key='data') or ''
            size = len(pem)
            if size == 0:
                assert False, f'ECC public key data not found: {self}'
            elif size == 66 or size == 130:  # or size == 128:
                # hex(4 + Q.x + Q.y)   -> 130 chars (uncompressed)
                # hex(3 + Q.x) / hex(2 + Q.x) -> 66 chars (compressed)
                data = bytes.fromhex(pem)
                verify_key = ecdsa.VerifyingKey.from_string(data, curve=self.curve, hashfunc=self.hash_func)
            else:
                verify_key = ecdsa.VerifyingKey.from_pem(pem, hashfunc=self.hash_func)
            self.__key = verify_key
        return verify_key

    @property
    def compressed(self) -> bool:
        """ whether the public key data is encoded in compressed format """
        return self.get_bool(key='compressed') or False

    @property  # Override
    def data(self) -> TransportableData:
        ted = self.__data
        if ted is None:
            ecc_key = self.ecc_key
            assert ecc_key is not None, f'ecc key error: {self}'
            if self.compressed:
                encoding = 'compressed'
            else:
                encoding = 'uncompressed'
            # get key data
            binary = ecc_key.to_string(encoding=encoding)
            ted = PlainData.create_with_bytes(binary=binary)
            self.__data = ted
        return ted

    # Override
    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            verifier = self.ecc_key
            return verifier.verify(signature=signature, data=data, hashfunc=self.hash_func, sigdecode=self.sig_decode)
        except ecdsa.BadSignatureError:
            return False


class ECCPrivateKey(BasePrivateKey):
    """ ECC Private Key

        keyInfo format : {
            algorithm  : "ECC",
            curve      : "secp256k1",
            data       : "..." // base64_encode()
        }
    """

    def __init__(self, key: StrMap):
        super().__init__(key)
        # lazy load
        self.__key: Optional[ecdsa.SigningKey] = None
        self.__data: Optional[TransportableData] = None
        self.__public_key: Optional[PublicKey] = None

    @classmethod
    def new_key(cls, curve_name: str = 'secp256k1') -> PrivateKey:
        """ generate new private key """
        curve = ecdsa.SECP256k1
        hash_func = hashlib.sha256
        ecc_key = ecdsa.SigningKey.generate(curve=curve, hashfunc=hash_func)
        # store private key in PKCS#8 format
        pem = ecc_key.to_pem(format='pkcs8').decode('utf-8')
        key = ECCPrivateKey(key={
            'algorithm': AsymmetricAlgorithms.ECC,
            'data': pem,
            'curve': curve_name,
            'digest': 'SHA256',
        })
        key.__key = ecc_key
        # key.__data = PlainData.create(binary=ecc_key.to_string())
        return key

    @property
    def curve(self):
        return ecdsa.SECP256k1

    @property
    def hash_func(self):
        return hashlib.sha256

    @property
    def sig_encode(self):
        return ecdsa.util.sigencode_der

    @property  # private
    def curve_name(self) -> str:
        """ get the curve name of this key, default is 'secp256k1' """
        return self.get_str(key='curve') or 'secp256k1'

    @property  # protected
    def ecc_key(self) -> ecdsa.SigningKey:
        """ Get the native ECC private key object (decoded from 'data') """
        sign_key = self.__key
        if sign_key is None:
            data = self.get_str(key='data') or ''
            if len(data) == 64:
                # key data in 'HEX' format: hex(s)
                data = bytes.fromhex(data)
                sign_key = ecdsa.SigningKey.from_string(data, curve=self.curve, hashfunc=self.hash_func)
            else:
                # key data in 'PEM' format
                sign_key = ecdsa.SigningKey.from_pem(data, hashfunc=self.hash_func)
            self.__key = sign_key
        return sign_key

    @property  # Override
    def data(self) -> TransportableData:
        ted = self.__data
        if ted is None:
            ecc_key = self.ecc_key
            assert ecc_key is not None, f'ecc key error: {self}'
            binary = ecc_key.to_string()
            ted = PlainData.create_with_bytes(binary=binary)
            self.__data = ted
        return ted

    @property  # Override
    def public_key(self) -> Union[PublicKey]:
        pub = self.__public_key
        if pub is None:
            sign_key = self.ecc_key
            pub_key = sign_key.get_verifying_key()
            pem = pub_key.to_pem().decode('utf-8')
            # pem = key.to_string(encoding='uncompressed').hex()
            info = {
                'algorithm': AsymmetricAlgorithms.ECC,
                'data': pem,
                'curve': self.curve_name,
                'digest': 'SHA256',
            }
            pub = ECCPublicKey(key=info)
            pub.__key = pub_key
            # pub.__data = PlainData.create(binary=pub_key.to_string())
            self.__public_key = pub
        return pub

    # Override
    def sign(self, data: bytes) -> bytes:
        signer = self.ecc_key
        return signer.sign(data=data, hashfunc=self.hash_func, sigencode=self.sig_encode)


"""
    Key Factories
    ~~~~~~~~~~~~~
"""


@final
class ECCPublicKeyFactory(PublicKeyFactory):

    # Override
    def parse_public_key(self, key: StrMap) -> Optional[PublicKey]:
        # check 'data', 'algorithm'
        if key.get('data') is None or key.get('algorithm') is None:
            # key.data should not be empty
            # key.algorithm should not be empty
            return None
        # OK
        return ECCPublicKey(key)


@final
class ECCPrivateKeyFactory(PrivateKeyFactory):

    # Override
    def generate_private_key(self) -> Optional[PrivateKey]:
        return ECCPrivateKey.new_key()

    # Override
    def parse_private_key(self, key: StrMap) -> Optional[PrivateKey]:
        # check 'data', 'algorithm'
        if key.get('data') is None or key.get('algorithm') is None:
            # key.data should not be empty
            # key.algorithm should not be empty
            return None
        # OK
        return ECCPrivateKey(key)
