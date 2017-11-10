# Original authors:
#   Trevor Perrin
#   Google - handling CertificateRequest.certificate_types
#   Google (adapted by Sam Rushing and Marcelo Fernandez) - NPN support
#   Dimitris Moraitis - Anon ciphersuites
#
# See the LICENSE file for legal information regarding use of this file.

#
# This has been heavily modified as part of sslxray!
#

"""Classes representing TLS messages."""

from .utils.compat import *
from .utils.cryptomath import *
from .errors import *
from .utils.codec import *
from .constants import *
from .x509 import X509
from .x509certchain import X509CertChain
from .utils.tackwrapper import *

class RecordHeader3(object):
    def __init__(self):
        self.type = 0
        self.version = (0,0)
        self.length = 0
        self.ssl2 = False

    def create(self, version, type, length):
        self.type = type
        self.version = version
        self.length = length
        return self

    def write(self):
        w = Writer()
        w.add(self.type, 1)
        w.add(self.version[0], 1)
        w.add(self.version[1], 1)
        w.add(self.length, 2)
        return w.bytes

    def parse(self, p):
        self.type = p.get(1)
        self.version = (p.get(1), p.get(1))
        self.length = p.get(2)
        self.ssl2 = False
        return self

class RecordHeader2(object):
    def __init__(self):
        self.length = 0
        self.type = 0

    def parse(self, p):
        lengthA = p.get(1)
        if lengthA & 0x80 != 0x80:
            raise SyntaxError()
        lengthB = p.get(1)
        self.length = ((lengthA & 0x7F) * 256) + lengthB
        self.type = p.get(1)


class Alert(object):
    def __init__(self):
        self.contentType = ContentType.alert
        self.level = 0
        self.description = 0

    def create(self, description, level=AlertLevel.fatal):
        self.level = level
        self.description = description
        return self

    def parse(self, p):
        p.setLengthCheck(2)
        self.level = p.get(1)
        self.description = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.level, 1)
        w.add(self.description, 1)
        return w.bytes


class HandshakeMsg(object):
    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType
    
    def postWrite(self, w, ssl2=False):
        headerWriter = Writer()
        if ssl2:
            headerWriter.add((len(w.bytes) + 1) | 0x8000, 2)
            headerWriter.add(self.handshakeType, 1)
        else:
            headerWriter.add(self.handshakeType, 1)
            headerWriter.add(len(w.bytes), 3)
        return headerWriter.bytes + w.bytes

class ClientHello(HandshakeMsg):
    def __init__(self, ssl2=False):
        HandshakeMsg.__init__(self, HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []         # a list of 16-bit values
        self.certificate_types = [CertificateType.x509]
        self.compression_methods = []   # a list of 8-bit values
        self.srp_username = None        # a string
        self.tack = False
        self.supports_npn = False
        self.alpn_protocols = []
        self.server_name = bytearray(0)
        self.ec = []

    def create(self, version, random, session_id, cipher_suites,
               certificate_types=None, srpUsername=None,
               tack=False, supports_npn=False, alpn_protocols=[], serverName=None, ec=[]):
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.certificate_types = certificate_types
        self.compression_methods = [0]
        if srpUsername:
            self.srp_username = bytearray(srpUsername, "utf-8")
        self.tack = tack
        self.ec = ec
        self.supports_npn = supports_npn
        self.alpn_protocols = alpn_protocols
        if serverName:
            self.server_name = bytearray(serverName, "utf-8")
        return self

    def parse(self, p):
        if self.ssl2:
            self.client_version = (p.get(1), p.get(1))
            cipherSpecsLength = p.get(2)
            sessionIDLength = p.get(2)
            randomLength = p.get(2)
            self.cipher_suites = p.getFixList(3, cipherSpecsLength//3)
            self.session_id = p.getFixBytes(sessionIDLength)
            self.random = p.getFixBytes(randomLength)
            if len(self.random) < 32:
                zeroBytes = 32-len(self.random)
                self.random = bytearray(zeroBytes) + self.random
            self.compression_methods = [0]#Fake this value

            #We're not doing a stopLengthCheck() for SSLv2, oh well..
        else:
            p.startLengthCheck(3)
            self.client_version = (p.get(1), p.get(1))
            self.random = p.getFixBytes(32)
            self.session_id = p.getVarBytes(1)
            self.cipher_suites = p.getVarList(2, 2)
            self.compression_methods = p.getVarList(1, 1)
            if not p.atLengthCheck():
                totalExtLength = p.get(2)
                soFar = 0
                while soFar != totalExtLength:
                    extType = p.get(2)
                    extLength = p.get(2)
                    index1 = p.index
                    if extType == ExtensionType.srp:
                        self.srp_username = p.getVarBytes(1)
                    elif extType == ExtensionType.cert_type:
                        self.certificate_types = p.getVarList(1, 1)
                    elif extType == ExtensionType.tack:
                        self.tack = True
                    elif extType == ExtensionType.supports_npn:
                        self.supports_npn = True
                    elif extType == ExtensionType.supports_alpn:
                        alpnData = p.getFixBytes(extLength)
                        pa = Parser(alpnData)
                        # ALPN record data is a string list
                        # it begins with a 2-byte length field describing the length of the whole list in bytes
                        # then each record is a string with a 1-byte length prefix
                        self.alpn_protocols = []
                        pa.startLengthCheck(2)
                        while True:
                            if pa.atLengthCheck():
                                break
                            alpnEntry = pa.getVarBytes(1)
                            self.alpn_protocols.append(alpnEntry)
                        pa.stopLengthCheck()
                    elif extType == ExtensionType.server_name:
                        serverNameListBytes = p.getFixBytes(extLength)
                        p2 = Parser(serverNameListBytes)
                        p2.startLengthCheck(2)
                        while 1:
                            if p2.atLengthCheck():
                                break # no host_name, oh well
                            name_type = p2.get(1)
                            hostNameBytes = p2.getVarBytes(2)
                            if name_type == NameType.host_name:
                                self.server_name = hostNameBytes
                                break
                        p2.stopLengthCheck()
                    else:
                        _ = p.getFixBytes(extLength)
                    index2 = p.index
                    if index2 - index1 != extLength:
                        raise SyntaxError("Bad length for extension_data")
                    soFar += 4 + extLength
            p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.ssl2:
            w.add(self.client_version[1], 1)
            w.add(self.client_version[0], 1)
            w.add(len(self.cipher_suites)*3, 2)
            w.addVarSeq(self.session_id, 1, 2)
            w.add(16, 2) # challenge length
            w.addFixSeq(self.cipher_suites, 3)
            w.addFixSeq([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 1)
        else:
            w.add(self.client_version[0], 1)
            w.add(self.client_version[1], 1)
            w.addFixSeq(self.random, 1)
            w.addVarSeq(self.session_id, 1, 1)
            w.addVarSeq(self.cipher_suites, 2, 2)
            w.addVarSeq(self.compression_methods, 1, 1)

            w2 = Writer() # For Extensions
            if self.certificate_types and self.certificate_types != \
                    [CertificateType.x509]:
                w2.add(ExtensionType.cert_type, 2)
                w2.add(len(self.certificate_types)+1, 2)
                w2.addVarSeq(self.certificate_types, 1, 1)
            if self.srp_username:
                w2.add(ExtensionType.srp, 2)
                w2.add(len(self.srp_username)+1, 2)
                w2.addVarSeq(self.srp_username, 1, 1)
            if self.supports_npn:
                w2.add(ExtensionType.supports_npn, 2)
                w2.add(0, 2)
            if self.alpn_protocols is not None and len(self.alpn_protocols) > 0:
                w2.add(ExtensionType.supports_alpn, 2)
                alpnExtensionListLength = 0
                for proto in self.alpn_protocols:
                    alpnExtensionListLength += len(proto) + 1
                alpnExtensionLength = alpnExtensionListLength + 2
                w2.add(alpnExtensionLength, 2)
                w2.add(alpnExtensionListLength, 2)
                for proto in self.alpn_protocols:
                    w2.addVarSeq(bytearray(proto), 1, 1)
                '''
                w2.addVarSeq([0x77, 0x32], 1, 1)
                # http/1.1
                w2.addVarSeq([0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31], 1, 1)
                '''
            if self.server_name:
                w2.add(ExtensionType.server_name, 2)
                w2.add(len(self.server_name)+5, 2)
                w2.add(len(self.server_name)+3, 2)
                w2.add(NameType.host_name, 1)
                w2.addVarSeq(self.server_name, 1, 2)
            if self.tack:
                w2.add(ExtensionType.tack, 2)
                w2.add(0, 2)
            if not self.ec is None and len(self.ec) > 0:
                w2.add(ExtensionType.ec_point_formats, 2)
                w2.add(2, 2) # extension length = 2
                w2.add(1, 1) # ec points format list length = 1
                w2.add(0, 1) # 0 = ec point format uncompressed
                w2.add(ExtensionType.elliptic_curves, 2)
                w2.add(2 + (len(self.ec) * 2), 2) # extension length = 4
                w2.add(len(self.ec) * 2, 2) # elliptic curves list length = 2
                for curve in self.ec:
                    w2.add(curve, 2) # elliptic curve to support
            if len(w2.bytes):
                w.add(len(w2.bytes), 2)
                w.bytes += w2.bytes
        return self.postWrite(w, ssl2=self.ssl2)

class BadNextProtos(Exception):
    def __init__(self, l):
        self.length = l

    def __str__(self):
        return 'Cannot encode a list of next protocols because it contains an element with invalid length %d. Element lengths must be 0 < x < 256' % self.length

class ServerHelloSSL2(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.ssl2 = True
        self.session_id_hit = False
        self.certificateType = 0
        self.version = (0,0)
        self.certificate_length = 0
        self.cipher_spec_length = 0
        self.connection_id_length = 0
        self.certificate = None
        self.cipher_specs = []
        self.connection_id = None

    def parse(self, p, h):
        p.setLengthCheck(h.length-3)
        self.session_id_hit = p.get(1) != 0
        self.certificateType = p.get(1)
        versionLow = p.get(1)
        versionHigh = p.get(1)
        self.version = (versionHigh, versionLow)
        self.certificate_length = p.get(2)
        self.cipher_spec_length = p.get(2)
        if self.cipher_spec_length % 3 != 0:
            raise SyntaxError()
        self.connection_id_length = p.get(2)
        if self.certificate_length > 0:
            self.certificate = p.getFixBytes(self.certificate_length)

        for i in range(0, self.cipher_spec_length / 3):
            self.cipher_specs.append(p.get(3))

        if self.connection_id_length > 0:
            self.connection_id = p.getFixBytes(self.connection_id_length)

        return self


class ServerHello(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello)
        self.server_version = (0,0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.certificate_type = CertificateType.x509
        self.compression_method = 0
        self.tackExt = None
        self.next_protos_advertised = None
        self.next_protos = None
        self.alpn_protocol = None

    def create(self, version, random, session_id, cipher_suite,
               certificate_type, tackExt, next_protos_advertised):
        self.server_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suite = cipher_suite
        self.certificate_type = certificate_type
        self.compression_method = 0
        self.tackExt = tackExt
        self.next_protos_advertised = next_protos_advertised
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.server_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        self.session_id = p.getVarBytes(1)
        self.cipher_suite = p.get(2)
        self.compression_method = p.get(1)
        if not p.atLengthCheck():
            totalExtLength = p.get(2)
            soFar = 0
            while soFar != totalExtLength:
                extType = p.get(2)
                extLength = p.get(2)
                if extType == ExtensionType.cert_type:
                    if extLength != 1:
                        raise SyntaxError()
                    self.certificate_type = p.get(1)
                elif extType == ExtensionType.tack and tackpyLoaded:
                    self.tackExt = TackExtension(p.getFixBytes(extLength))
                elif extType == ExtensionType.supports_npn:
                    self.next_protos = self.__parse_next_protos(p.getFixBytes(extLength))
                elif extType == ExtensionType.supports_alpn:
                    self.alpn_protocol = self.__parse_alpn_proto(p.getFixBytes(extLength))
                else:
                    p.getFixBytes(extLength)
                soFar += 4 + extLength
        p.stopLengthCheck()
        return self

    def __parse_alpn_proto(self, b):
        protos = []
        pa = Parser(b)
        pa.startLengthCheck(2)
        while 1:
            if pa.atLengthCheck():
                break
            alpnEntry = int(pa.getVarBytes(1))
            protos.append(alpnEntry)
        pa.stopLengthCheck()
        if len(protos) == 1:
            return protos[0]
        if len(protos) == 0:
            return None
        # at this point len(protos) must be >1, this is a violation of the RFC!
        # only one protocol must be provided in a ServerHello ALPN extension record.
        raise SyntaxError()

    def __parse_next_protos(self, b):
        protos = []
        while True:
            if len(b) == 0:
                break
            l = b[0]
            b = b[1:]
            if len(b) < l:
                raise BadNextProtos(len(b))
            protos.append(b[:l])
            b = b[l:]
        return protos

    def __next_protos_encoded(self):
        b = bytearray()
        for e in self.next_protos_advertised:
            if len(e) > 255 or len(e) == 0:
                raise BadNextProtos(len(e))
            b += bytearray( [len(e)] ) + bytearray(e)
        return b

    def write(self):
        w = Writer()
        w.add(self.server_version[0], 1)
        w.add(self.server_version[1], 1)
        w.addFixSeq(self.random, 1)
        w.addVarSeq(self.session_id, 1, 1)
        w.add(self.cipher_suite, 2)
        w.add(self.compression_method, 1)

        w2 = Writer() # For Extensions
        if self.certificate_type and self.certificate_type != \
                CertificateType.x509:
            w2.add(ExtensionType.cert_type, 2)
            w2.add(1, 2)
            w2.add(self.certificate_type, 1)
        if self.tackExt:
            b = self.tackExt.serialize()
            w2.add(ExtensionType.tack, 2)
            w2.add(len(b), 2)
            w2.bytes += b
        if self.next_protos_advertised is not None:
            encoded_next_protos_advertised = self.__next_protos_encoded()
            w2.add(ExtensionType.supports_npn, 2)
            w2.add(len(encoded_next_protos_advertised), 2)
            w2.addFixSeq(encoded_next_protos_advertised, 1)
        if len(w2.bytes):
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes        
        return self.postWrite(w)


class Certificate(HandshakeMsg):
    def __init__(self, certificateType):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self.certChain = None

    def create(self, certChain):
        self.certChain = certChain
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.certificateType == CertificateType.x509:
            chainLength = p.get(3)
            index = 0
            certificate_list = []
            while index != chainLength:
                certBytes = p.getVarBytes(3)
                x509 = X509()
                x509.parseBinary(certBytes)
                certificate_list.append(x509)
                index += len(certBytes)+3
            if certificate_list:
                self.certChain = X509CertChain(certificate_list)
        else:
            raise AssertionError()

        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = 0
            if self.certChain:
                certificate_list = self.certChain.x509List
            else:
                certificate_list = []
            #determine length
            for cert in certificate_list:
                bytes = cert.writeBytes()
                chainLength += len(bytes)+3
            #add bytes
            w.add(chainLength, 3)
            for cert in certificate_list:
                bytes = cert.writeBytes()
                w.addVarSeq(bytes, 1, 3)
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateRequest(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.certificate_request)
        #Apple's Secure Transport library rejects empty certificate_types, so
        #default to rsa_sign.
        self.certificate_types = [ClientCertificateType.rsa_sign]
        self.certificate_authorities = []

    def create(self, certificate_types, certificate_authorities):
        self.certificate_types = certificate_types
        self.certificate_authorities = certificate_authorities
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.certificate_types = p.getVarList(1, 1)
        ca_list_length = p.get(2)
        index = 0
        self.certificate_authorities = []
        while index != ca_list_length:
          ca_bytes = p.getVarBytes(2)
          self.certificate_authorities.append(ca_bytes)
          index += len(ca_bytes)+2
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addVarSeq(self.certificate_types, 1, 1)
        caLength = 0
        #determine length
        for ca_dn in self.certificate_authorities:
            caLength += len(ca_dn)+2
        w.add(caLength, 2)
        #add bytes
        for ca_dn in self.certificate_authorities:
            w.addVarSeq(ca_dn, 1, 2)
        return self.postWrite(w)

class ServerKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite):
        HandshakeMsg.__init__(self, HandshakeType.server_key_exchange)
        self.cipherSuite = cipherSuite
        self.srp_N = 0
        self.srp_g = 0
        self.srp_s = bytearray(0)
        self.srp_B = 0
        # Anon DH params:
        self.dh_p = 0
        self.dh_g = 0
        self.dh_Ys = 0
        self.signature = bytearray(0)

    def createSRP(self, srp_N, srp_g, srp_s, srp_B):
        self.srp_N = srp_N
        self.srp_g = srp_g
        self.srp_s = srp_s
        self.srp_B = srp_B
        return self
    
    def createDH(self, dh_p, dh_g, dh_Ys):
        self.dh_p = dh_p
        self.dh_g = dh_g
        self.dh_Ys = dh_Ys
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_N = bytesToNumber(p.getVarBytes(2))
            self.srp_g = bytesToNumber(p.getVarBytes(2))
            self.srp_s = p.getVarBytes(1)
            self.srp_B = bytesToNumber(p.getVarBytes(2))
            if self.cipherSuite in CipherSuite.srpCertSuites:
                self.signature = p.getVarBytes(2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_p = bytesToNumber(p.getVarBytes(2))
            self.dh_g = bytesToNumber(p.getVarBytes(2))
            self.dh_Ys = bytesToNumber(p.getVarBytes(2))
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_N), 1, 2)
            w.addVarSeq(numberToByteArray(self.srp_g), 1, 2)
            w.addVarSeq(self.srp_s, 1, 1)
            w.addVarSeq(numberToByteArray(self.srp_B), 1, 2)
            if self.cipherSuite in CipherSuite.srpCertSuites:
                w.addVarSeq(self.signature, 1, 2)
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_p), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_g), 1, 2)
            w.addVarSeq(numberToByteArray(self.dh_Ys), 1, 2)
            if self.cipherSuite in []: # TODO support for signed_params
                w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

    def hash(self, clientRandom, serverRandom):
        oldCipherSuite = self.cipherSuite
        self.cipherSuite = None
        try:
            bytes = clientRandom + serverRandom + self.write()[4:]
            return MD5(bytes) + SHA1(bytes)
        finally:
            self.cipherSuite = oldCipherSuite

class ServerHelloDone(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello_done)

    def create(self):
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        return self.postWrite(w)

class ClientKeyExchange(HandshakeMsg):
    def __init__(self, cipherSuite, version=None):
        HandshakeMsg.__init__(self, HandshakeType.client_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_A = 0
        self.encryptedPreMasterSecret = bytearray(0)

    def createSRP(self, srp_A):
        self.srp_A = srp_A
        return self

    def createRSA(self, encryptedPreMasterSecret):
        self.encryptedPreMasterSecret = encryptedPreMasterSecret
        return self
    
    def createDH(self, dh_Yc):
        self.dh_Yc = dh_Yc
        return self
    
    def parse(self, p):
        p.startLengthCheck(3)
        if self.cipherSuite in CipherSuite.srpAllSuites:
            self.srp_A = bytesToNumber(p.getVarBytes(2))
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2)):
                self.encryptedPreMasterSecret = p.getVarBytes(2)
            elif self.version == (3,0):
                self.encryptedPreMasterSecret = \
                    p.getFixBytes(len(p.bytes)-p.index)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            self.dh_Yc = bytesToNumber(p.getVarBytes(2))            
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        if self.cipherSuite in CipherSuite.srpAllSuites:
            w.addVarSeq(numberToByteArray(self.srp_A), 1, 2)
        elif self.cipherSuite in CipherSuite.certSuites:
            if self.version in ((3,1), (3,2)):
                w.addVarSeq(self.encryptedPreMasterSecret, 1, 2)
            elif self.version == (3,0):
                w.addFixSeq(self.encryptedPreMasterSecret, 1)
            else:
                raise AssertionError()
        elif self.cipherSuite in CipherSuite.anonSuites:
            w.addVarSeq(numberToByteArray(self.dh_Yc), 1, 2)            
        else:
            raise AssertionError()
        return self.postWrite(w)

class CertificateVerify(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.signature = bytearray(0)

    def create(self, signature):
        self.signature = signature
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.signature = p.getVarBytes(2)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addVarSeq(self.signature, 1, 2)
        return self.postWrite(w)

class ChangeCipherSpec(object):
    def __init__(self):
        self.contentType = ContentType.change_cipher_spec
        self.type = 1

    def create(self):
        self.type = 1
        return self

    def parse(self, p):
        p.setLengthCheck(1)
        self.type = p.get(1)
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.add(self.type,1)
        return w.bytes


class NextProtocol(HandshakeMsg):
    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.next_protocol)
        self.next_proto = None

    def create(self, next_proto):
        self.next_proto = next_proto
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        self.next_proto = p.getVarBytes(1)
        _ = p.getVarBytes(1)
        p.stopLengthCheck()
        return self

    def write(self, trial=False):
        w = Writer()
        w.addVarSeq(self.next_proto, 1, 1)
        paddingLen = 32 - ((len(self.next_proto) + 2) % 32)
        w.addVarSeq(bytearray(paddingLen), 1, 1)
        return self.postWrite(w)

class Finished(HandshakeMsg):
    def __init__(self, version):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = bytearray(0)

    def create(self, verify_data):
        self.verify_data = verify_data
        return self

    def parse(self, p):
        p.startLengthCheck(3)
        if self.version == (3,0):
            self.verify_data = p.getFixBytes(36)
        elif self.version in ((3,1), (3,2)):
            self.verify_data = p.getFixBytes(12)
        else:
            raise AssertionError()
        p.stopLengthCheck()
        return self

    def write(self):
        w = Writer()
        w.addFixSeq(self.verify_data, 1)
        return self.postWrite(w)

class ApplicationData(object):
    def __init__(self):
        self.contentType = ContentType.application_data
        self.bytes = bytearray(0)

    def create(self, bytes):
        self.bytes = bytes
        return self
        
    def splitFirstByte(self):
        newMsg = ApplicationData().create(self.bytes[:1])
        self.bytes = self.bytes[1:]
        return newMsg

    def parse(self, p):
        self.bytes = p.bytes
        return self

    def write(self):
        return self.bytes
