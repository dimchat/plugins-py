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
    Decentralized Instant Messaging (Python Plugins)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

from dimp.ext import *

from .mem import *

from .crypto import *
from .format import *

from .mkm import *
from .dkd import *
from .ext import *

from .ext_msg import ContentParser, CommandParser
from .ext_loader import ExtensionLoader
from .plugin_loader import PluginLoader


name = "DIMPlugins"

__author__ = 'Albert Moky'

__all__ = [

    'TransportableDataHelper',
    'FormatExtensions', 'shared_format_extensions',

    'SymmetricKeyHelper', 'PublicKeyHelper', 'PrivateKeyHelper',
    'CryptoExtensions', 'shared_crypto_extensions',

    'AddressHelper', 'IDHelper',
    'MetaHelper', 'DocumentHelper',
    'AccountExtensions', 'shared_account_extensions',

    'GeneralCryptoHelper',
    'GeneralAccountHelper',

    'ContentHelper', 'EnvelopeHelper',
    'InstantMessageHelper', 'SecureMessageHelper', 'ReliableMessageHelper',
    'MessageExtensions', 'shared_message_extensions',

    'GeneralMessageHelper',

    'TransportableFileHelper',

    'CommandHelper', 'GeneralCommandHelper',
    'QuoteHelper', 'QuotePurifier',

    #
    #   Memory Cache
    #

    'MemoryCache',
    'ThanosCache',

    'MemoryCacheExtension',

    #
    #   Crypto
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

    #
    #   Format
    #

    'Base64Coder', 'Base58Coder', 'HexCoder',
    'JSONCoder', 'UTF8Coder',
    # 'CoderMixIn',

    'BaseNetworkDataFactory', 'BaseNetworkFileFactory',
    # 'TransportableMixIn',

    #
    #   MingKeMing
    #

    'BTCAddress', 'ETHAddress',
    'BaseAddressFactory',

    'GeneralIdentifierFactory',

    'DefaultMeta', 'BTCMeta', 'ETHMeta',
    'BaseMetaFactory',

    'GeneralDocumentFactory',

    #
    #   DaoKeDao
    #

    'GeneralCommandFactory',
    'HistoryCommandFactory',
    'GroupCommandFactory',

    'MessageFactory',

    #
    #   Core Extensions
    #

    'CryptographyKeyGeneralFactory', 'FormatGeneralFactory',
    'AccountGeneralFactory',
    'MessageGeneralFactory', 'CommandGeneralFactory',

    #
    #   Loaders
    #

    'ContentParser', 'CommandParser',
    'ExtensionLoader',
    'PluginLoader',

]
