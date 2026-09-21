# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2023 Albert Moky
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
    Data Format
    ~~~~~~~~~~~

    Base64, EmbedData, PNF
"""

from .coder import Base64Coder, Base58Coder, HexCoder
from .coder import JSONCoder, UTF8Coder
# from .coder import CoderMixIn

# from .duri import StringPairing, MutableStringPairing
from .duri import Header, DataURI

from .base64_data import Base64Data

from .embed import EmbedData

from .pnf import PortableNetworkFile
from .pnf_wrapper import PortableNetworkFileWrapper

from .factories import BaseNetworkDataFactory, BaseNetworkFileFactory
# from .factories import TransportableMixIn


__all__ = [

    #
    #   Data Format
    #

    'Base64Coder', 'Base58Coder', 'HexCoder',
    'JSONCoder', 'UTF8Coder',
    # 'CoderMixIn',

    # 'StringPairing', 'MutableStringPairing',
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

]
