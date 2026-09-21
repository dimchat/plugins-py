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

"""
    DIM-AP
    ~~~~~~

    Decentralized Instant Messaging Algorithm Plugins
"""

from .crypto import *
from .format import *

from .ext import *

from .crypto.digest import DigestMixIn
from .format.coder import CoderMixIn
from .format.factories import TransportableMixIn
from .format.duri import StringPairing, MutableStringPairing
from .ext.crypto import SymmetricKeyFactoryMap
from .ext.crypto import PrivateKeyFactoryMap
from .ext.crypto import PublicKeyFactoryMap

from .plugin_core import CoreMixIn
from .plugin_keys import CryptoMixIn
from .plugin_loader import PluginLoader


name = "DIM-AP"

__author__ = 'Albert Moky'

__all__ = [

    'AsymmetricAlgorithms', 'SymmetricAlgorithms',
    'EncodeAlgorithms',

    #
    #   Crypto Keys
    #

    'BaseKey',
    'BaseSymmetricKey', 'BaseAsymmetricKey',
    'BasePublicKey', 'BasePrivateKey',

    'PlainKey', 'PlainKeyFactory',
    'AESKey', 'AESKeyFactory',

    'RSAPublicKey', 'RSAPublicKeyFactory',
    'RSAPrivateKey', 'RSAPrivateKeyFactory',

    'ECCPublicKey', 'ECCPublicKeyFactory',
    'ECCPrivateKey', 'ECCPrivateKeyFactory',

    #
    #   Message Digester
    #

    'SHA256Digester', 'KECCAK256Digester', 'RIPEMD160Digester',
    'DigestMixIn',

    #
    #   Data Format
    #

    'Base64Coder', 'Base58Coder', 'HexCoder',
    'JSONCoder', 'UTF8Coder',
    'CoderMixIn',

    'StringPairing', 'MutableStringPairing',
    'Header', 'DataURI',

    'Base64Data',

    'EmbedData',

    'PortableNetworkFile',
    'PortableNetworkFileWrapper',

    'BaseNetworkDataFactory', 'BaseNetworkFileFactory',
    'TransportableMixIn',

    #
    #   Core Extensions
    #

    'SymmetricKeyFactoryMap',
    'PrivateKeyFactoryMap',
    'PublicKeyFactoryMap',

    'GeneralCryptoHelper',

    'GeneralFormatHelper',

    #
    #   Plugin Loader
    #

    'CoreMixIn',
    'CryptoMixIn',
    'PluginLoader',

]
