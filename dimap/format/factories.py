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

"""
    Transportable Resource
    ~~~~~~~~~~~~~~~~~~~~~~

    TED, PNF
"""

import base64

from typing import Optional

from dimp import StrMap
from dimp import DecryptKey
from dimp import URI
from dimp import TransportableData, TransportableDataFactory
from dimp import TransportableFile, TransportableFileFactory
from dimp import TransportableFileWrapper
from dimp import TransportableFileWrapperFactory
from dimp import shared_format_extensions

from ..crypto import EncodeAlgorithms

from .duri import DataURI
from .embed import EmbedData
from .base64_data import Base64Data

from .pnf import PortableNetworkFile
from .pnf_wrapper import PortableNetworkFileWrapper


class BaseNetworkDataFactory(TransportableDataFactory):
    """
    Transportable Data Factory (TED)

    Creates a `TransportableData` from raw bytes with optional
    encoding/mime-type parameters, or parses a data URI / Base-64
    string back into a `TransportableData` instance.
    """

    # Override
    def create_transportable_data(self, data: bytes, encoding: Optional[str],
                                  mime_type: Optional[str],
                                  parameters: Optional[StrMap]) -> TransportableData:
        if encoding is None:
            # default with Base-64 encoding
            return Base64Data.create_with_bytes(binary=data)
        elif mime_type is None:
            mime_type = 'text/plain'
        assert EncodeAlgorithms.BASE_64 == encoding, f'TED encoding error: {encoding}'
        encoded = base64.b64encode(data).decode('utf-8')
        uri = f'data:{mime_type};{encoding},{encoded}'
        return EmbedData.create_with_uri(uri=DataURI.parse(uri=uri))

    # Override
    def parse_transportable_data(self, ted: str) -> Optional[TransportableData]:
        # check data URI
        uri = DataURI.parse(uri=ted)
        if uri is not None:
            # "data:image/jpeg;base64,..."
            assert uri.is_base64, f'TED encoding error: {uri.parameters}'
            return EmbedData.create_with_uri(uri=uri)
        # TODO: check Base-64 format
        # "{BASE64_ENCODED}"
        return Base64Data.create_with_string(encoded=ted)


class BaseNetworkFileFactory(TransportableFileFactory):
    """
    Portable Network File Factory (PNF)

    Creates a `PortableNetworkFile` from data/filename/URL/password,
    or parses a PNF dictionary into a `PortableNetworkFile` instance.
    """

    # Override
    def create_transportable_file(self, data: Optional[TransportableData], filename: Optional[str], url: Optional[URI],
                                  password: Optional[DecryptKey]) -> TransportableFile:
        return PortableNetworkFile(None, data=data, filename=filename, url=url, password=password)

    # Override
    def parse_transportable_file(self, pnf: StrMap) -> Optional[TransportableFile]:
        # check 'data', 'URL', 'filename'
        if pnf.get('data') is None and pnf.get('URL') is None and pnf.get('filename') is None:
            # pnf.data and pnf.URL and pnf.filename should not be empty at the same time
            assert False, f'PNF error: {pnf}'
        else:
            return PortableNetworkFile(dictionary=pnf)


class _PNFWrapperFactory(TransportableFileWrapperFactory):
    """
    Default implementation of `TransportableFileWrapperFactory`.

    Creates `PortableNetworkFileWrapper` instances with the given parameters.
    """

    # Override
    def create_transportable_file_wrapper(self, content: StrMap,
                                          data: Optional[TransportableData],
                                          filename: Optional[str],
                                          url: Optional[URI],
                                          password: Optional[DecryptKey]) -> TransportableFileWrapper:
        # create wrapper for the content
        wrapper = PortableNetworkFileWrapper(content)
        # file data
        if data is not None:
            wrapper.data = data
        # file name
        if filename is not None:
            wrapper.filename = filename
        # remote URL
        if url is not None:
            wrapper.url = url
        # decrypt key
        if password is not None:
            wrapper.password = password
        # OK
        return wrapper


# noinspection PyMethodMayBeStatic
class TransportableMixIn:
    """ Transportable Plugins """

    # protected
    def register_ted_factory(self):
        # TED
        factory = BaseNetworkDataFactory()
        TransportableData.set_factory(factory=factory)

    # protected
    def register_pnf_factory(self):
        # PNF
        factory = BaseNetworkFileFactory()
        PortableNetworkFile.set_factory(factory=factory)

    # protected
    def register_pnf_wrapper_factory(self):
        # PNF Wrapper
        shared_format_extensions.pnf_wrapper_factory = _PNFWrapperFactory()
