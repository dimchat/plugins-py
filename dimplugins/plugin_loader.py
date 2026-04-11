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

from .format.coder import CoderMixIn
from .format.trans import TransportableMixIn

from .crypto.digest import DigestMixIn

from .plugin_keys import CryptoMixIn


# noinspection PyMethodMayBeStatic
class PluginLoader(CoderMixIn, TransportableMixIn, DigestMixIn, CryptoMixIn):

    def load(self):
        """ Register plugins """
        self._load_data_coders()

        self._load_message_digesters()

        self._load_crypto_key_factories()

    def _load_data_coders(self):
        """ Data coders """
        self.register_base58_coder()
        self.register_base64_coder()
        self.register_hex_coder()

        self.register_utf8_coder()
        self.register_json_coder()

        self.register_pnf_factory()
        self.register_ted_factory()

    def _load_message_digesters(self):
        """ Data digesters """
        self.register_sha256_digester()

        self.register_keccak256_digester()

        self.register_ripemd160_digester()

    def _load_crypto_key_factories(self):
        """ Crypto key parsers """
        # Symmetric keys
        self.register_aes_key_factory()
        self.register_plain_key_factory()
        # Asymmetric keys
        self.register_ecc_key_factories()
        self.register_rsa_key_factories()
