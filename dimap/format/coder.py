# -*- coding: utf-8 -*-
# ==============================================================================
# MIT License
#
# Copyright (c) 2020 Albert Moky
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
    Base Coder
    ~~~~~~~~~~

    Base58
"""

from typing import Optional, Any

import json
import base64
import base58

from dimp import final
from dimp import DataCoder, Hex, Base58, Base64
from dimp import ObjectCoder, JSON
from dimp import StringCoder, UTF8


@final
class Base64Coder(DataCoder):
    """
    Base-64 data coder.

    Encodes bytes to a Base-64 string, and decodes a Base-64 string
    back to bytes.
    """

    # Override
    def encode(self, data: bytes) -> str:
        """ BASE-64 Encode """
        return base64.b64encode(data).decode('utf-8')

    # Override
    def decode(self, string: str) -> Optional[bytes]:
        """ BASE-64 Decode """
        return base64.b64decode(string)


@final
class Base58Coder(DataCoder):
    """
    Base-58 data coder.

    Encodes bytes to a Base-58 string, and decodes a Base-58 string
    back to bytes.
    """

    # Override
    def encode(self, data: bytes) -> str:
        """ BASE-58 Encode """
        return base58.b58encode(data).decode('utf-8')

    # Override
    def decode(self, string: str) -> Optional[bytes]:
        """ BASE-58 Decode """
        return base58.b58decode(string)


@final
class HexCoder(DataCoder):
    """
    Hexadecimal data coder.

    Encodes bytes to a hex string (lowercase), and decodes a hex string
    back to bytes. An odd-length hex string is treated as a leading
    nibble (e.g. "abc" -> [0x0a, 0xbc]).
    """

    # Override
    def encode(self, data: bytes) -> str:
        """ HEX Encode """
        # return binascii.b2a_hex(data).decode('utf-8')
        return data.hex()

    # Override
    def decode(self, string: str) -> Optional[bytes]:
        """ HEX Decode

        An odd-length hex string is treated as a leading nibble
        (e.g. "abc" -> [0x0a, 0xbc]); returns None on invalid chars.
        """
        # return binascii.a2b_hex(string)
        length = len(string)
        odd = length & 1 == 1
        if odd:
            # treat the first char as a leading nibble
            try:
                value0 = int(string[0], 16)
            except ValueError:
                return None
            try:
                rest = bytes.fromhex(string[1:])
            except ValueError:
                return None
            return bytes([value0]) + rest
        try:
            return bytes.fromhex(string)
        except ValueError:
            return None


@final
class JSONCoder(ObjectCoder):
    """
    JSON object coder.

    Serializes an object to a JSON string, and parses a JSON string
    back to a dynamic object.
    """

    # Override
    def encode(self, container: Any) -> str:
        """ JsON encode """
        return json.dumps(container)

    # Override
    def decode(self, string: str) -> Optional[Any]:
        """ JsON decode """
        return json.loads(string)


@final
class UTF8Coder(StringCoder):
    """
    UTF-8 string coder.

    Encodes a string into UTF-8 bytes, and decodes bytes back
    to a string (returns None if the bytes are not valid UTF-8).
    """

    # Override
    def encode(self, string: str) -> bytes:
        """ UTF-8 encode """
        return string.encode('utf-8')

    # Override
    def decode(self, data: bytes) -> Optional[str]:
        """ UTF-8 decode (returns None if not valid UTF-8) """
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None


# noinspection PyMethodMayBeStatic
class CoderMixIn:
    """
    Coder Plugins

    Registers the data coders (UTF-8, JSON, Hex, Base-58,
    Base-64) into the global coder holders.
    """

    # protected
    def register_utf8_coder(self):
        """ Set UTF-8 coder. """
        # UTF8
        UTF8.coder = UTF8Coder()

    # protected
    def register_json_coder(self):
        """ Set JSON coder. """
        # JSON
        JSON.coder = JSONCoder()

    # protected
    def register_hex_coder(self):
        """ Set HEX coder. """
        # HEX coding
        Hex.coder = HexCoder()

    # protected
    def register_base58_coder(self):
        """ Set Base-58 coder. """
        # Base58 coding
        Base58.coder = Base58Coder()

    # protected
    def register_base64_coder(self):
        """ Set Base-64 coder. """
        # Base64 coding
        Base64.coder = Base64Coder()
