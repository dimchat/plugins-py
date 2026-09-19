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

from typing import Optional, Union

from dimp import URI
from dimp import StrMap, MutableStrMap
from dimp import Dictionary

from dimp import DecryptKey
from dimp import TransportableData
from dimp import JSONMap

from dimp import TransportableFile
from dimp import TransportableFileWrapper

from .duri import DataURI


class PortableNetworkFile(Dictionary, TransportableFile):

    def __init__(self, dictionary: Optional[StrMap],
                 data: Optional[TransportableData] = None, filename: Optional[str] = None,
                 url: Optional[URI] = None, password: Optional[DecryptKey] = None,
                 wrapper: Optional[TransportableFileWrapper] = None):
        super().__init__(dictionary=dictionary)
        if wrapper is None:
            wrapper = TransportableFileWrapper.create(super().to_map(),
                                                      data=data, filename=filename,
                                                      url=url, password=password)
        self.__wrapper = wrapper

    # protected
    @property
    def uri_string(self) -> Optional[str]:
        # serialize
        wrapper = self.__wrapper
        info = wrapper.to_map()
        # check 'URL'
        remote = self.url
        if remote is not None and len(remote) > 0:
            count = len(info)
            if count == 1:
                # this PNF info contains 'URL' only,
                # so return the URI string here.
                return remote
            elif count == 2 and info.get('filename') is not None:
                # ignore 'filename'
                return remote
            # this PNF info contains other params,
            # cannot serialize it as a string.
            return None
        # check data
        text = self.get_str(key='data')
        if text is not None and text.startswith('data:'):
            count = len(info)
            if count == 1:
                # this PNF info contains 'data' only,
                # and it is a data URI,
                # so return the URI string here.
                return text
            elif count == 2 and 'filename' in info:
                # check 'filename'
                filename = self.get_str(key='filename')
                if filename is None or len(filename) == 0:
                    # nothing changed
                    return text
                # add 'filename' to data URI
                text = self.new_data_uri(text=text, filename=filename)
                return text
            # this PNF info contains other params,
            # cannot serialize it as a string.
            return None
        # the file data was saved into local storage,
        # so there is just a 'filename' here,
        # cannot build URI string
        return None

    # protected
    # noinspection PyMethodMayBeStatic
    def new_data_uri(self, text: str, filename: str) -> str:
        """ Build a new data URI by updating the 'filename' parameter.

        :param text:     the original data URI string.
        :param filename: the new filename to set (empty to remove it).
        :return: the rebuilt data URI.
        """
        uri = DataURI.parse(uri=text)
        assert uri is not None, f'data URI error: {text}'
        # copy extra values
        extra = {}
        if uri.parameters is not None:
            extra.update(uri.parameters)
        if len(filename) == 0:
            # erase 'filename'
            extra.pop('filename', None)
        else:
            # update 'filename'
            extra['filename'] = filename
        # build header
        mime_type = uri.mime_type
        if len(mime_type) == 0:
            # make sure 'mime-type' is the first header
            mime_type = 'text/plain'
        header = mime_type
        for name, value in extra.items():
            header += f';{name}={value}'
        if uri.is_base64:
            header += ';base64'
        # build new data URI
        pos = text.find(',')
        body = text[pos + 1:]
        return f'data:{header},{body}'

    # Override
    def __str__(self) -> str:
        uri_string = self.uri_string
        if uri_string is not None:
            return uri_string
        # return JSON string
        wrapper = self.__wrapper
        info = wrapper.to_map()
        return JSONMap.encode(info)

    # Override
    def to_map(self) -> MutableStrMap:
        """ call wrapper to serialize 'data' & 'key" """
        wrapper = self.__wrapper
        return wrapper.to_map()
        # return self.__dictionary

    # Override
    def serialize(self) -> Union[str, StrMap]:
        uri_string = self.uri_string
        if uri_string is not None:
            return uri_string
        # return inner map
        wrapper = self.__wrapper
        info = wrapper.to_map()
        return dict(info)

    #
    #   File data
    #

    # Override
    @property
    def data(self) -> Optional[TransportableData]:
        wrapper = self.__wrapper
        return wrapper.data

    # Override
    @data.setter
    def data(self, content: Optional[TransportableData]):
        wrapper = self.__wrapper
        wrapper.data = content

    #
    #   File name
    #

    # Override
    @property
    def filename(self) -> Optional[str]:
        wrapper = self.__wrapper
        return wrapper.filename

    # Override
    @filename.setter
    def filename(self, name: Optional[str]):
        wrapper = self.__wrapper
        wrapper.filename = name

    #
    #   Download URL
    #

    # Override
    @property
    def url(self) -> Optional[URI]:
        wrapper = self.__wrapper
        return wrapper.url

    # Override
    @url.setter
    def url(self, locator: Optional[URI]):
        wrapper = self.__wrapper
        wrapper.url = locator

    #
    #   Decrypt Key
    #

    # Override
    @property
    def password(self) -> Optional[DecryptKey]:
        wrapper = self.__wrapper
        return wrapper.password

    # Override
    @password.setter
    def password(self, key: Optional[DecryptKey]):
        wrapper = self.__wrapper
        wrapper.password = key
