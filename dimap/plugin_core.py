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

from .ext.crypto import CryptographyKeyGeneralFactory


# noinspection PyMethodMayBeStatic
class CoreMixIn:
    """ Core Extensions """

    # protected
    def register_crypto_helpers(self):
        # crypto
        helper = CryptographyKeyGeneralFactory()
        ext = crypto_extensions()
        ext.symmetric_helper = helper
        ext.private_helper = helper
        ext.public_helper = helper
        ext.helper = helper


def crypto_extensions() -> Union[SymmetricKeyExtension, PublicKeyExtension, PrivateKeyExtension,
                                 GeneralCryptoExtension]:
    return shared_crypto_extensions
