# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2026 Albert Moky
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

from typing import Union

from dimp import SymmetricKeyExtension, PublicKeyExtension, PrivateKeyExtension
from dimp import GeneralCryptoExtension, shared_crypto_extensions
from dimp import shared_format_extensions

from .ext import GeneralCryptoHelper
from .ext import GeneralFormatHelper


# noinspection PyMethodMayBeStatic
class CoreMixIn:
    """ Core Plugins

    Registers the general helpers (crypto & format) into the
    shared extension holders.
    """

    # protected
    def register_format_helpers(self):
        """ Register the format helpers.

        Sets a `GeneralFormatHelper` as the default TED/PNF helper.
        """
        # format
        helper = GeneralFormatHelper()
        shared_format_extensions.ted_helper = helper
        shared_format_extensions.pnf_helper = helper

    # protected
    def register_crypto_helpers(self):
        """ Register the crypto helpers.

        Sets a `GeneralCryptoHelper` as the default key handler
        and symmetric/private/public key helpers.
        """
        # crypto
        helper = GeneralCryptoHelper()
        ext = crypto_extensions()
        ext.symmetric_helper = helper
        ext.private_helper = helper
        ext.public_helper = helper
        ext.handler = helper


def crypto_extensions() -> Union[SymmetricKeyExtension, PublicKeyExtension, PrivateKeyExtension,
                                 GeneralCryptoExtension]:
    return shared_crypto_extensions
