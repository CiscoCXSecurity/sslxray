# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""PyCrypto RSA implementation."""

from .cryptomath import *

from .rsakey import *
from .python_rsakey import Python_RSAKey

if pycryptoLoaded:

    from Crypto.PublicKey import RSA

    class PyCrypto_RSAKey(RSAKey):
        def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
            if not d:
                self.rsa = RSA.construct( (n, e) )
            else:
                self.rsa = RSA.construct( (n, e, d, p, q) )

        def __getattr__(self, name):
            return getattr(self.rsa, name)

        def hasPrivateKey(self):
            return self.rsa.has_private()

        def _rawPrivateKeyOp(self, m):
            s = numberToString(m, numBytes(self.n))
            c = stringToNumber(self.rsa.decrypt((s,)))
            return c

        def _rawPublicKeyOp(self, c):
            s = numberToString(c, numBytes(self.n))
            m = stringToNumber(self.rsa.encrypt(s, None)[0])
            return m

        def generate(bits):
            key = PyCrypto_RSAKey()
            def f(numBytes):
                return bytes(getRandomBytes(numBytes))
            key.rsa = RSA.generate(bits, f)
            return key
        generate = staticmethod(generate)
