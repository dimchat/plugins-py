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

"""
    Message Digest
    ~~~~~~~~~~~~~~

    SHA-256, Keccak256, RipeMD-160, ...
"""

import hashlib

from Crypto.Hash import keccak

from dimp import final
from dimp import MessageDigester
from dimp import SHA256, KECCAK256, RIPEMD160


@final
class SHA256Digester(MessageDigester):
    """SHA-256 message digester.

    Computes the SHA-256 hash of the input data (32 bytes).
    """

    # Override
    def digest(self, data: bytes) -> bytes:
        """ SHA-256 """
        hash_obj = hashlib.sha256(data)
        return hash_obj.digest()


@final
class KECCAK256Digester(MessageDigester):
    """Keccak-256 message digester.

    Computes the Keccak-256 hash of the input data (32 bytes).
    """

    # Override
    def digest(self, data: bytes) -> bytes:
        """ Keccak256 digest """
        hash_obj = keccak.new(digest_bits=256)
        hash_obj.update(data)
        return hash_obj.digest()


@final
class RIPEMD160Digester(MessageDigester):
    """RIPEMD-160 message digester.

    Computes the RIPEMD-160 hash of the input data (20 bytes).
    """

    # Override
    def digest(self, data: bytes) -> bytes:
        """ RipeMD-160 """
        hash_obj = hashlib.new('ripemd160')
        hash_obj.update(data)
        return hash_obj.digest()


# noinspection PyMethodMayBeStatic
class DigestMixIn:
    """Digest Plugins

    Registers the message digesters (SHA-256, Keccak-256,
    RIPEMD-160) into the global digester holders.
    """

    # protected
    def register_sha256_digester(self):
        """ set SHA-256 digester """
        # SHA256
        SHA256.digester = SHA256Digester()

    # protected
    def register_keccak256_digester(self):
        """ set Keccak-256 digester """
        # KECCAK256
        KECCAK256.digester = KECCAK256Digester()

    # protected
    def register_ripemd160_digester(self):
        """ set RipeMD-160 digester """
        # RIPEMD160
        RIPEMD160.digester = RIPEMD160Digester()
