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

from dimp.ext import *

from .crypto import *
from .format import *

from .ext import *

from .plugin_loader import PluginLoader


name = "DIM-AP"

__author__ = 'Albert Moky'

__all__ = [

    #
    #   Format
    #

    'TransportableDataHelper',
    'FormatExtensions', 'shared_format_extensions',

    #
    #   Crypto
    #

    'SymmetricKeyHelper', 'PublicKeyHelper', 'PrivateKeyHelper',

    'SymmetricKeyExtension', 'PublicKeyExtension', 'PrivateKeyExtension',
    'CryptoExtensions', 'shared_crypto_extensions',

    'EncryptedBundleHandler', 'DefaultBundleHandler',
    'BundleExtension',

    #
    #   Ming-Ke-Ming
    #

    'AddressHelper', 'IDHelper',
    'MetaHelper', 'DocumentHelper',

    'AddressExtension', 'IDExtension',
    'MetaExtension', 'DocumentExtension',
    'AccountExtensions', 'shared_account_extensions',

    'CryptoKeyHandler',
    'GeneralCryptoExtension',
    'AccountHandler', 'GeneralAccountExtension',

    #
    #   Dao-Ke-Dao
    #

    'ContentHelper', 'EnvelopeHelper',
    'InstantMessageHelper', 'SecureMessageHelper', 'ReliableMessageHelper',

    'ContentExtension',
    'InstantMessageExtension', 'SecureMessageExtension', 'ReliableMessageExtension',
    'MessageExtensions', 'shared_message_extensions',

    'MessageHandler', 'MessageHandlerExtension',

    # ----------------------------------------------------------------

    'TransportableFileHelper',
    'CommandHelper', 'CommandHandler',
    'CommandExtension', 'GeneralCommandExtension',

    ################################
    #
    #   Crypto
    #
    ################################

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
    #   Message Digest
    #

    'SHA256Digester', 'KECCAK256Digester', 'RIPEMD160Digester',
    # 'DigestMixIn',

    ################################
    #
    #   Format
    #
    ################################

    'Base64Coder', 'Base58Coder', 'HexCoder',
    'JSONCoder', 'UTF8Coder',
    # 'CoderMixIn',

    'StringPairing', 'MutableStringPairing',
    'Header', 'DataURI',

    'Base64Data',

    'EmbedData',

    #
    #   PNF
    #

    'PortableNetworkFile',
    'PortableNetworkFileWrapper',

    'BaseNetworkDataFactory', 'BaseNetworkFileFactory',
    # 'TransportableMixIn',

    ################################
    #
    #   Core Extensions
    #
    ################################

    'GeneralCryptoHelper',
    'GeneralFormatHelper',

    #
    #   Loaders
    #

    # 'CoreMixIn',
    # 'CryptoMixIn',

    'PluginLoader',

]
