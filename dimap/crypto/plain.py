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

from typing import Optional

from dimp import final
from dimp import StrMap, MutableStrMap
from dimp import SymmetricKey, SymmetricKeyFactory
from dimp import TransportableData
from dimp import PlainData

from .algorithms import SymmetricAlgorithms
from .keys import BaseKey, BaseSymmetricKey


@final
class PlainKey(BaseSymmetricKey):
    """
        Symmetric key for broadcast message,
        which will do nothing when en/decoding message data
    """

    # def __init__(self, key: StrMap):
    #     super().__init__(key)

    @classmethod
    def new_key(cls) -> SymmetricKey:
        return PlainKey(key={
            'algorithm': SymmetricAlgorithms.PLAIN,
        })

    __instance = None

    @classmethod
    def get_instance(cls) -> SymmetricKey:
        """ Get the singleton PlainKey instance.

            PlainKey is a stateless key which does nothing when
            encrypting/decrypting, so there is only one global instance.
        """
        if cls.__instance is None:
            cls.__instance = cls.new_key()
        return cls.__instance

    @property  # Override
    def data(self) -> TransportableData:
        # empty data
        return PlainData.zero()

    # Override
    def encrypt(self, plaintext: bytes, extra: Optional[MutableStrMap] = None) -> bytes:
        return plaintext

    # Override
    def decrypt(self, ciphertext: bytes, params: Optional[StrMap] = None) -> Optional[bytes]:
        return ciphertext


"""
    Key Factory
    ~~~~~~~~~~~
"""


@final
class PlainKeyFactory(SymmetricKeyFactory):
    """Plain Key Factory

    Generates/parses the singleton `PlainKey` for broadcast messages.
    """

    # def __init__(self):
    #     super().__init__()

    # Override
    def generate_symmetric_key(self) -> Optional[SymmetricKey]:
        return PlainKey.get_instance()

    # Override
    def parse_symmetric_key(self, key: StrMap) -> Optional[SymmetricKey]:
        # check 'algorithm'
        algorithm = BaseKey.get_key_algorithm(key=key)
        if algorithm != SymmetricAlgorithms.PLAIN:
            # algorithm not matched
            return None
        # OK
        return PlainKey(key)
