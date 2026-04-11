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

import random
from typing import Optional, Dict

from Crypto.Cipher import AES

from dimp import SymmetricAlgorithms
from dimp import SymmetricKey, SymmetricKeyFactory
from dimp import TransportableData
from dimp import Base64Data

from .keys import BaseSymmetricKey


def random_bytes(size: int) -> bytes:
    # return bytes(numpy.random.bytes(size))
    bits = random.getrandbits(size * 8)
    return bits.to_bytes(length=size, byteorder='little', signed=False)


class AESKey(BaseSymmetricKey):
    """ AES Key """

    AES_CBC_PKCS7 = "AES/CBC/PKCS7Padding"

    def __init__(self, key: Dict):
        super().__init__(key)
        # TODO: check algorithm parameters
        #   1. check mode = 'CBC'
        #   2. check padding = 'PKCS7Padding'
        #
        # lazy load
        self.__data: Optional[TransportableData] = None

    @classmethod
    def new_key(cls, size: int = 32) -> SymmetricKey:
        """ generate a new random key """
        pwd = random_bytes(size=size)
        ted = Base64Data.create(binary=pwd)
        key = AESKey(key={
            'algorithm': SymmetricAlgorithms.AES,
            'data': ted.serialize(),
            # 'mod': 'CBC',
            # 'padding': 'PKCS7',
        })
        key.__data = ted
        return key

    @property
    def size(self) -> int:
        # TODO: get from key data
        count = self.get_int(key='keySize')
        if count is None:
            return self.bits >> 3  # 32
        else:
            return count

    @property
    def bits(self) -> int:
        count = self.get_int(key='sizeInBits')
        if count is None:
            return 256  # AES-256
        else:
            return count

    @property
    def block_size(self) -> int:
        # TODO: get from iv data
        count = self.get(key='blockSize')
        if count is None:
            return AES.block_size  # 16
        else:
            return count

    @property  # Override
    def data(self) -> TransportableData:
        ted = self.__data
        if ted is None:
            base64 = self.get('data')
            assert base64 is not None, 'key data not found: %s' % self
            ted = TransportableData.parse(base64)
            assert ted is not None, 'key data error: %s' % base64
            self.__data = ted
        return ted

    def _get_init_vector(self, params: Optional[Dict]) -> Optional[bytes]:
        """ get IV from params """
        # get base64 encoded IV from params
        if params is None:
            assert False, 'params must provided to fetch IV for AES'
        else:
            base64 = params.get('IV')
            if base64 is None:
                base64 = params.get('iv')
        if base64 is None:
            # compatible with old version
            base64 = self.get_str(key='iv')
            if base64 is None:
                base64 = self.get_str(key='IV')
        # decode IV data
        ted = TransportableData.parse(base64)
        if ted is not None:
            iv = ted.data
            if iv is not None:
                return iv
        assert base64 is None, 'IV data error: %s' % base64

    def _zero_init_vector(self):
        # zero IV:
        #           b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
        return self.block_size * chr(0).encode('utf-8')

    def _new_init_vector(self, extra: Optional[Dict]) -> bytes:
        # random IV data
        iv = random_bytes(size=self.block_size)
        # put encoded IV into extra
        if extra is None:
            assert False, 'extra dict must provided to store IV for AES'
        else:
            ted = Base64Data.create(binary=iv)
            extra['IV'] = ted.object
        # OK
        return iv

    # Override
    def encrypt(self, plaintext: bytes, extra: Optional[Dict] = None) -> bytes:
        # 1. if 'IV' not found in extra params, new a random 'IV'
        key_iv = self._get_init_vector(params=extra)
        if key_iv is None:
            key_iv = self._new_init_vector(extra=extra)
        # 2. get key data
        key_data = self.data
        buffer = key_data.binary
        # 3. try to encrypt
        data = pkcs7_pad(data=plaintext, block_size=AES.block_size)
        key = AES.new(buffer, AES.MODE_CBC, key_iv)
        return key.encrypt(data)

    # Override
    def decrypt(self, ciphertext: bytes, params: Optional[Dict] = None) -> Optional[bytes]:
        # 1. if 'IV' not found in extra params, use an empty 'IV'
        key_iv = self._get_init_vector(params=params)
        if key_iv is None:
            key_iv = self._zero_init_vector()
        # 2. get key data
        key_data = self.data
        buffer = key_data.binary
        # 3. try to decrypt
        try:
            key = AES.new(buffer, AES.MODE_CBC, key_iv)
            plaintext = key.decrypt(ciphertext)
            return pkcs7_unpad(data=plaintext)
        except ValueError:
            return None


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    assert data is not None, 'data cannot be None'
    amount = block_size - len(data) % block_size
    if amount == 0:
        amount = block_size
    pad = chr(amount).encode('utf-8')
    return data + pad * amount


def pkcs7_unpad(data: bytes) -> bytes:
    assert data is not None and len(data) > 0, 'data empty'
    amount = data[-1]
    assert len(data) >= amount
    return data[:-amount]


"""
    Key Factory
    ~~~~~~~~~~~
"""


class AESKeyFactory(SymmetricKeyFactory):

    # Override
    def generate_symmetric_key(self) -> Optional[SymmetricKey]:
        return AESKey.new_key()

    # Override
    def parse_symmetric_key(self, key: Dict) -> Optional[SymmetricKey]:
        # check 'data'
        if 'data' not in key:
            # key.data should not be empty
            return None
        # OK
        return AESKey(key=key)
