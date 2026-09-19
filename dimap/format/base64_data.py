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

from typing import Optional

from mkm.format import Base64

from dimp import BaseData

from ..crypto.algorithms import EncodeAlgorithms


class Base64Data(BaseData):
    """ Base-64 encoding """

    @property
    def encoding(self) -> str:
        return EncodeAlgorithms.BASE_64

    # Override
    def to_bytes(self) -> Optional[bytes]:
        data = self._binary
        if data is None:
            base64 = self._string
            assert base64 is not None, f'Base64Data error: {self}'
            data = Base64.decode(string=base64)
            self._binary = data
        return data

    # Override
    def to_str(self) -> str:
        base64 = self._string
        if base64 is None or len(base64) == 0:
            data = self._binary
            assert data is not None, f'Base64Data error: {self}'
            base64 = Base64.encode(data=data)
            self._string = base64
        return base64

    #
    #   Factory
    #

    @classmethod
    def create(cls, string: str = None, binary: bytes = None):
        assert not (string is None and binary is None), \
            'encoded string and binary data should not be empty at the same time'
        return Base64Data(string=string, binary=binary)
