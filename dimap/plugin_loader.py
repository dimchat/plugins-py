# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2024 Albert Moky
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

from .plugin_core import CoreMixIn

from .format.coder import CoderMixIn
from .format.factories import TransportableMixIn

from .crypto.digest import DigestMixIn

from .plugin_keys import CryptoMixIn


# noinspection PyMethodMayBeStatic
class PluginLoader(CoreMixIn, CoderMixIn, DigestMixIn, TransportableMixIn, CryptoMixIn):
    """ Core Plugins Loader

    Loads all plugins of the DimPlugins library by registering
    the data coders, message digesters, key factories and
    TED/PNF factories into the corresponding extension holders.
    """

    def load(self):
        """ Register plugins """
        self._load_core_plugins()

        self._load_digest_plugins()

        self._load_coder_plugins()

        self._load_format_plugins()

        self._load_crypto_plugins()

    # protected
    def _load_core_plugins(self):
        """ Core extensions """
        self.register_format_helpers()

        self.register_crypto_helpers()

    # protected
    def _load_coder_plugins(self):
        """ Data coders """
        self.register_base58_coder()
        self.register_base64_coder()
        self.register_hex_coder()

        self.register_utf8_coder()
        self.register_json_coder()

    # protected
    def _load_digest_plugins(self):
        """ Message digesters """
        self.register_sha256_digester()

        self.register_keccak256_digester()

        self.register_ripemd160_digester()

    # protected
    def _load_format_plugins(self):
        """ Load the format plugins. """
        self.register_ted_factory()

        self.register_pnf_factory()
        self.register_pnf_wrapper_factory()

    # protected
    def _load_crypto_plugins(self):
        """ Crypto key parsers """
        # Symmetric keys
        self.register_aes_key_factory()
        self.register_plain_key_factory()
        # Asymmetric keys
        self.register_rsa_key_factories()
        self.register_ecc_key_factories()
