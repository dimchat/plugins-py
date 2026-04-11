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

from dimp import SymmetricAlgorithms, AsymmetricAlgorithms
from dimp import SymmetricKey, PublicKey, PrivateKey

from .crypto import AESKey, AESKeyFactory, PlainKeyFactory
from .crypto import ECCPublicKeyFactory, ECCPrivateKeyFactory
from .crypto import RSAPublicKeyFactory, RSAPrivateKeyFactory


# noinspection PyMethodMayBeStatic
class CryptoMixIn:
    """ Crypto Plugins """

    # protected
    def register_aes_key_factory(self):
        # Symmetric Key: AES
        factory = AESKeyFactory()
        SymmetricKey.set_factory(algorithm=SymmetricAlgorithms.AES, factory=factory)
        SymmetricKey.set_factory(algorithm=AESKey.AES_CBC_PKCS7, factory=factory)
        # SymmetricKey.set_factory(algorithm='AES/CBC/PKCS7Padding', factory=factory)

    # protected
    def register_plain_key_factory(self):
        # Symmetric Key: Plain
        factory = PlainKeyFactory()
        SymmetricKey.set_factory(algorithm=SymmetricAlgorithms.PLAIN, factory=factory)

    # protected
    def register_ecc_key_factories(self):
        # Public Key: ECC
        ecc_pub = ECCPublicKeyFactory()
        PublicKey.set_factory(algorithm=AsymmetricAlgorithms.ECC, factory=ecc_pub)
        PublicKey.set_factory(algorithm='SHA256withECDSA', factory=ecc_pub)
        # Private Key: ECC
        ecc_pri = ECCPrivateKeyFactory()
        PrivateKey.set_factory(algorithm=AsymmetricAlgorithms.ECC, factory=ecc_pri)
        PrivateKey.set_factory(algorithm='SHA256withECDSA', factory=ecc_pri)

    # protected
    def register_rsa_key_factories(self):
        # Public Key: RSA
        rsa_pub = RSAPublicKeyFactory()
        PublicKey.set_factory(algorithm=AsymmetricAlgorithms.RSA, factory=rsa_pub)
        PublicKey.set_factory(algorithm='SHA256withRSA', factory=rsa_pub)
        PublicKey.set_factory(algorithm='RSA/ECB/PKCS1Padding', factory=rsa_pub)
        # Private Key: RSA
        rsa_pri = RSAPrivateKeyFactory()
        PrivateKey.set_factory(algorithm=AsymmetricAlgorithms.RSA, factory=rsa_pri)
        PrivateKey.set_factory(algorithm='SHA256withRSA', factory=rsa_pri)
        PrivateKey.set_factory(algorithm='RSA/ECB/PKCS1Padding', factory=rsa_pri)
