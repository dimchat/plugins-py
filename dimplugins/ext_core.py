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

from dimp import shared_crypto_extensions, shared_format_extensions
from dimp import shared_account_extensions
from dimp import shared_message_extensions

from .ext import CryptographyKeyGeneralFactory, FormatGeneralFactory
from .ext import AccountGeneralFactory
from .ext import MessageGeneralFactory, CommandGeneralFactory


# noinspection PyMethodMayBeStatic
class CoreMixIn:
    """ Core Extensions """

    # protected
    def register_crypto_helpers(self):
        # crypto
        helper = CryptographyKeyGeneralFactory()
        shared_crypto_extensions.symmetric_helper = helper
        shared_crypto_extensions.private_helper = helper
        shared_crypto_extensions.public_helper = helper
        shared_crypto_extensions.helper = helper

    # protected
    def register_format_helpers(self):
        # format
        helper = FormatGeneralFactory()
        shared_format_extensions.pnf_helper = helper
        shared_format_extensions.ted_helper = helper

    # protected
    def register_account_helpers(self):
        # mkm
        helper = AccountGeneralFactory()
        shared_account_extensions.address_helper = helper
        shared_account_extensions.id_helper = helper
        shared_account_extensions.meta_helper = helper
        shared_account_extensions.doc_helper = helper
        shared_account_extensions.helper = helper

    # protected
    def register_message_helpers(self):
        # dkd
        helper = MessageGeneralFactory()
        shared_message_extensions.content_helper = helper
        shared_message_extensions.envelope_helper = helper
        shared_message_extensions.instant_helper = helper
        shared_message_extensions.secure_helper = helper
        shared_message_extensions.reliable_helper = helper
        shared_message_extensions.helper = helper

    # protected
    def register_command_helpers(self):
        # cmd
        helper = CommandGeneralFactory()
        shared_message_extensions.cmd_helper = helper
        shared_message_extensions.command_helper = helper
