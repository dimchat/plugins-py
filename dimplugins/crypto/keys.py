# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2022 Albert Moky
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

from abc import ABC
from typing import Dict

from dimp import Mapper, Dictionary
from dimp import CryptographyKey, EncryptKey, DecryptKey, SignKey, VerifyKey
from dimp import SymmetricKey, AsymmetricKey, PublicKey, PrivateKey
from dimp import GeneralCryptoHelper
from dimp import GeneralCryptoExtension, shared_crypto_extensions


"""
    Base Keys
    ~~~~~~~~~
"""


# noinspection PyAbstractClass
class BaseKey(Dictionary, CryptographyKey, ABC):

    def __init__(self, key: Dict):
        super().__init__(key)

    @property  # Override
    def algorithm(self) -> str:
        info = self.to_dict()
        return BaseKey.get_key_algorithm(key=info)

    #
    #   Conveniences
    #

    @classmethod
    def get_key_algorithm(cls, key: Dict) -> str:
        helper = crypto_helper()
        algorithm = helper.get_key_algorithm(key=key)
        return '' if algorithm is None else algorithm

    @classmethod
    def match_encrypt_key(cls, encrypt_key: EncryptKey, decrypt_key: DecryptKey) -> bool:
        """ match encrypt key """
        return GeneralCryptoHelper.match_symmetric_keys(encrypt_key=encrypt_key, decrypt_key=decrypt_key)

    @classmethod
    def match_sign_key(cls, sign_key: SignKey, verify_key: VerifyKey) -> bool:
        """ match sign key """
        return GeneralCryptoHelper.match_asymmetric_keys(sign_key=sign_key, verify_key=verify_key)

    @classmethod
    def symmetric_keys_equal(cls, a: SymmetricKey, b: SymmetricKey) -> bool:
        """ symmetric key equals """
        if a is b:
            # same object
            return True
        # compare by encryption
        return cls.match_encrypt_key(encrypt_key=a, decrypt_key=b)

    @classmethod
    def private_keys_equal(cls, a: PrivateKey, b: PrivateKey) -> bool:
        """ asymmetric key equals """
        if a is b:
            # same object
            return True
        # compare by signature
        return cls.match_sign_key(sign_key=a, verify_key=b.public_key)


def crypto_extensions() -> GeneralCryptoExtension:
    return shared_crypto_extensions


def crypto_helper() -> GeneralCryptoHelper:
    ext = crypto_extensions()
    return ext.helper


# noinspection PyAbstractClass
class BaseSymmetricKey(Dictionary, SymmetricKey, ABC):

    def __init__(self, key: Dict):
        super().__init__(key)

    # Override
    def __eq__(self, other) -> bool:
        if isinstance(other, Mapper):
            if self is other:
                # same object
                return True
            elif isinstance(other, SymmetricKey):
                return BaseKey.symmetric_keys_equal(other, self)
            # compare with inner map
            other = other.to_dict()
        return self.to_dict().__eq__(other)

    # Override
    def __ne__(self, other) -> bool:
        if isinstance(other, Mapper):
            if self is other:
                # same object
                return False
            elif isinstance(other, SymmetricKey):
                return not BaseKey.symmetric_keys_equal(other, self)
            # compare with inner map
            other = other.to_dict()
        return self.to_dict().__ne__(other)

    @property  # Override
    def algorithm(self) -> str:
        info = self.to_dict()
        return BaseKey.get_key_algorithm(key=info)

    # Override
    def match_encrypt_key(self, key: EncryptKey) -> bool:
        return BaseKey.match_encrypt_key(encrypt_key=key, decrypt_key=self)


# noinspection PyAbstractClass
class BaseAsymmetricKey(Dictionary, AsymmetricKey, ABC):

    def __init__(self, key: Dict):
        super().__init__(key)

    @property  # Override
    def algorithm(self) -> str:
        info = self.to_dict()
        return BaseKey.get_key_algorithm(key=info)


# noinspection PyAbstractClass
class BasePublicKey(Dictionary, PublicKey, ABC):

    def __init__(self, key: Dict):
        super().__init__(key)

    @property  # Override
    def algorithm(self) -> str:
        info = self.to_dict()
        return BaseKey.get_key_algorithm(key=info)

    # Override
    def match_sign_key(self, key: SignKey) -> bool:
        return BaseKey.match_sign_key(sign_key=key, verify_key=self)


# noinspection PyAbstractClass
class BasePrivateKey(Dictionary, PrivateKey, ABC):

    def __init__(self, key: Dict):
        super().__init__(key)

    # Override
    def __eq__(self, other) -> bool:
        if isinstance(other, Mapper):
            if self is other:
                # same object
                return True
            elif isinstance(other, PrivateKey):
                return BaseKey.private_keys_equal(other, self)
            # compare with inner map
            other = other.to_dict()
        return self.to_dict().__eq__(other)

    # Override
    def __ne__(self, other) -> bool:
        if isinstance(other, Mapper):
            if self is other:
                # same object
                return False
            elif isinstance(other, PrivateKey):
                return not BaseKey.private_keys_equal(other, self)
            # compare with inner map
            other = other.to_dict()
        return self.to_dict().__ne__(other)

    @property  # Override
    def algorithm(self) -> str:
        info = self.to_dict()
        return BaseKey.get_key_algorithm(key=info)
