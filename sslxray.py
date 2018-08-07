from tlslite.messages import *
from tlslite.api import *
from tlslite.constants import *
from tlslite import TLSConnection
from tlslite.utils.cryptomath import *
from sslxray_consts import *
from sslxray_ciphers import *
from reporting import *
from issue_templates import *
from zlib import *
import argparse
import binascii
import socket

#DEBUG = True
DEBUG = False

if DEBUG:
    from time import *
    import hexdump

VERSION = "0.1.5"

supportedEllipticCurveCiphers = []
serverRandomValues = []
serverAdvertisedNPN = False
serverALPNProtocols = set([])

def listProtocols():
    """
    Prints a list of the current known protocols, sorted by ascending version.
    """
    print("Known protocols:")
    for protocol in sorted(KnownProtocols, key=lambda proto: (proto['id'][0] * 1000) + proto['id'][1]):
        print("%s (%d,%d)" % (protocol['name'], protocol['id'][0], protocol['id'][1]))


def listSuites():
    """
    Prints a list of the current known cipher suites, sorted alphabetically by name.
    """
    print("Known cipher suites:")
    for suite in sorted(KnownCiphers, key=lambda cipher: cipher.Name):
        print("%s (0x%04X)" % (suite.Name, suite.ID))


def resolveHost():
    """
    Resolves the currently selected host to an IP address.
    :rtype: str
    :return: String representing the IP address of the host.
    """
    return socket.gethostbyname(args.host)


def filterProtocolsByUserOptions():
    """
    Filters out any protocols which were disabled by the user.
    """
    # by default, no protocols should be disabled
    if args.disabledProtocols is None:
        return KnownProtocols

    # some protocols were disabled by the user, so filter
    protos = []
    for kp in KnownProtocols:
        if not kp['name'] in args.disabledProtocols:
            protos.append(kp)
    return protos


def tryConnectionWithCipherSuites(version, cipherSuites, sendSSLv2=False, curves=[], enableNPN=False, alpnProtocols=[]):
    """
    Attempts an SSL/TLS connection given a set of cipher suites.
    :rtype: bool
    :return: True if the connection succeeded, otherwise false.
    """

    global supportedEllipticCurveCiphers
    global serverRandomValues
    global serverAdvertisedNPN
    global serverALPNProtocols

    # build a ClientHello packet with appropriate settings and the selected cipher suites
    hello = ClientHello(ssl2=sendSSLv2)

    extensions = []

    if len(alpnProtocols) > 0:
        alpnExtension = ALPNExtension().create(alpnProtocols)
        extensions.append(alpnExtension)

    sigAlgsExtension = SignatureAlgorithmsExtension().create([
        (HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
        (HashAlgorithm.sha1, SignatureAlgorithm.rsa),
        (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
        (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
        (HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
        (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
        (HashAlgorithm.sha512, SignatureAlgorithm.ecdsa),
        (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
    ])
    extensions.append(sigAlgsExtension)

    ecGroupsExtension = SupportedGroupsExtension().create([GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1])
    extensions.append(ecGroupsExtension)

    ecPointFormatsExtension = ECPointFormatsExtension().create([0])
    extensions.append(ecPointFormatsExtension)

    hello.create(version, getRandomBytes(32), bytearray(0), cipherSuites, certificate_types=[CertificateType.x509], serverName=args.sniName, extensions=extensions)
    helloData = hello.write()
    headerData = bytearray()
    if sendSSLv2:
        headerData = RecordHeader2().create(len(helloData)).write()
    else:
        headerData = RecordHeader3().create((3,1), ContentType.handshake, len(helloData)).write()
    packet = headerData + helloData

    try:
        # connect and send the packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( (args.host, args.port) )
        sock.send(packet)

        # receive the response packet
        response = sock.recv(4096)

        # some connection closure cases cause a response to come back as zero-length or None
        # rather than throwing an exception. we handle this here
        if response is None or len(response) == 0:
            return False

        # if we sent an SSLv2 request that the server didn't understand it, it'll likely have sent
        # back a TLS ALERT packet. our logic later assumes that an SSLv2 packet is always returned
        # if we sent an SSLv2 packet, so this is to catch the error early.
        if sendSSLv2:
            # HACK: this is just ContentType=Alert(21), ProtocolVersion=3.x
            if response[:2] == b'\x15\x03':
                return False

        # parse the response packet header
        packetParser = Parser(bytearray(response))
        responseHeader = None
        if sendSSLv2:
            responseHeader = RecordHeader2()
        else:
            responseHeader = RecordHeader3()

        try:
            responseHeader.parse(packetParser)
        except SyntaxError:
            # parse fails with SyntaxError exception if an unexpected response comes back
            sock.close()
            return False

        # did the response come back as a negotiation failure alert?
        if responseHeader.type == ContentType.alert:
            sock.close()
            return False

        # did the response come as a different version than we requested?
        # this check only works for non-SSLv2 as the version data isn't in the header for SSLv2
        if not sendSSLv2 and responseHeader.version != version:
            sock.close()
            return False

        # if we sent SSLv2, we need to do some additional parsing and checks
        if sendSSLv2:
            serverHello = ServerHello2().parse(packetParser)
            # did we get back the same version we asked for?
            if serverHello.version != version:
                # different version (wtf?)
                return False
            # did the server respond with a different SSL suite to the one we asked for?
            if set(serverHello.cipher_specs).isdisjoint(cipherSuites):
                # there are no matching cipher suites, this cipher isn't supported
                return False
        
        # ok, we got an accepted one. if it's not SSLv2 we want to do some checks
        if not sendSSLv2:
            packetParser.get(1)
            serverHello = ServerHello().parse(packetParser)
            serverRandomValues.append(serverHello.random)
            alpnExtensions = [] if serverHello.extensions is None else [ext for ext in serverHello.extensions if isinstance(ext, ALPNExtension)]
            if len(alpnExtensions) > 0:
                # ALPN was advertised, so add it to the supported protocols
                kp = [knownProto for knownProto in KnownALPNProtocols if bytearray(knownProto.Name, 'ascii') in alpnExtensions[0].protocol_names]
                if len(kp) == 1:
                    serverALPNProtocols.add(kp[0])
                elif len(kp) == 0:
                    print("\tServer advertised unknown ALPN protocol '%s' - please contact sslxray dev to get this included!" % str(alpnExtensions[0].protocol_names[0]))
                else:
                    raise ValueError("Duplicate ALPN definition somewhere in KnownALPNProtocols!")
                if DEBUG:
                    print("\tServer advertised ALPN protocol '%s'" % serverHello.alpn_protocol)
            if serverHello.next_protos is not None:
                serverAdvertisedNPN = True
                if DEBUG:
                    print("\tServer advertised NPN support.")

        sock.close()
    except socket.error as e:
        return False

    # everything seemed to work and the cipher was accepted
    return True


def testCipherSupport():
    """
    Enumerates the cipher suites accepted by the server.
    """

    print("Enumerating ciphers...")
    protocols = filterProtocolsByUserOptions()
    for protocol in protocols:
        print("Testing protocol %s..." % protocol['name'])
        ssl2 = protocol['id'] == (2,0)
        for cipher in KnownCiphers:
            if not ssl2 and (cipher.ID & 0xFF0000 != 0 or cipher.Protocol in [ProtocolType.SSL, ProtocolType.SSL2]):
                # we ignore SSLv2 ciphers for non-SSLv2 protocol scans; they're the wrong size.
                continue
            curves = []
            if cipher.KeyExchange in [ KeyExchangeType.ECDH, KeyExchangeType.ECDHE ]:
                curves=[c['id'] for c in KnownCurves]
            if tryConnectionWithCipherSuites( protocol['id'], [cipher.ID], sendSSLv2=ssl2, curves=curves ):
                print("\t%s [0x%08x]" % (cipher.Name, cipher.ID))
                if cipher.KeyExchange in [ KeyExchangeType.ECDH, KeyExchangeType.ECDHE ]:
                    supportedEllipticCurveCiphers.append( {'protocol': protocol['id'], 'cipher': cipher} )


def testEllipticCurveSupport():
    """
    Enumerates the cipher suites accepted by the server.
    """
    MIN_SECURE_CURVE_SIZE = 224 # as per NIST 800-57 Part 1 Rev 4, Jan 2016
    shortCurves = []
    print("Testing elliptic curve support...")
    if len(supportedEllipticCurveCiphers) == 0:
        print("\tNo EC cipher supported, skipping test.")
    for cipherInfo in supportedEllipticCurveCiphers:
        protocolId = cipherInfo['protocol']
        cipher = cipherInfo['cipher']
        print("Testing elliptic curve support for %s ..." % (cipher.Name))
        for curve in KnownCurves:
            if tryConnectionWithCipherSuites( protocolId, [cipher.ID], sendSSLv2=False, curves=[ curve['id'] ] ):
                print("\t%s [0x%08x] curve: [0x%04x] %s" % (cipher.Name, cipher.ID, curve['id'], curve['name']))
                if curve['size'] < MIN_SECURE_CURVE_SIZE:
                    shortCurves.append(curve)
    # this makes a temporary dictionary of form 'curve.id : curve' to uniquify the curves list
    shortCurves = list({c['id']:c for c in shortCurves}.values())
    if len(shortCurves) > 0:
        print("")
        print("Insecure curves (size < %d) supported:" % MIN_SECURE_CURVE_SIZE)
        for shortCurve in shortCurves:
            print("\t%s [0x%04x] - %d bits" % (shortCurve['name'], shortCurve['id'], shortCurve['size']))
    print("")


def testNPNSupport():
    """
    Reports if NPN was advertised during the enumeration phase.
    The flag here is set inside tryConnectionWithCipherSuites()
    """
    if not serverAdvertisedNPN:
        tryConnectionWithCipherSuites((3, 1), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, enableNPN=True)
        tryConnectionWithCipherSuites((3, 2), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, enableNPN=True)
        tryConnectionWithCipherSuites((3, 3), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, enableNPN=True)

    if serverAdvertisedNPN:
        print("Server advertised NPN support.")
    else:
        print("Server did not advertise NPN support.")


def testALPNSupport():
    """
    Reports if ALPN was advertised during the enumeration phase.
    The flag here is set inside tryConnectionWithCipherSuites()
    """
    if len(serverALPNProtocols) == 0:
        for alpnProto in KnownALPNProtocols:
            for tlsProtocol in [(3,1),(3,2),(3,3),(3,4)]:
                if tryConnectionWithCipherSuites(tlsProtocol, [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, alpnProtocols=[bytearray(alpnProto.Name, 'ascii')]):
                    serverALPNProtocols.add(alpnProto)

    if len([proto for proto in serverALPNProtocols if proto.Outdated]) > 0:
        alpnSupportString = ", ".join([proto.Name for proto in serverALPNProtocols if proto.Outdated])
        print("The server supports the following outdated ALPN protocols:", alpnSupportString)

    if len(serverALPNProtocols) > 0:
        print("Server advertised ALPN support.")
    else:
        print("Server did not advertise ALPN support.")


def testMACValidation():
    """
    Tests whether the server properly rejects messages when their MAC is modified.
    """
    print("Testing validation of individual MAC bits...")
    failBits = []
    for maskBit in range(0, 96):
        rejected = False
        try:
            # formulate a bit mask based on the current mask bit index
            mask = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            maskIndex = int((maskBit - (maskBit % 8)) / 8)
            mask[maskIndex] = (0x80 >> (maskBit % 8))

            if args.verbose:
                maskBinString = ''.join(format(x, 'b').zfill(8) for x in mask)
                print("\tTesting bit %d, mask: %s" % (maskBit, maskBinString))
            else:
                print("+", end="")

            # connect to the server and do a handshake
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect( (args.host, args.port) )
            tls = TLSConnection(sock)

            # assign mask as tweak
            tls.macTweak = bytearray(mask)

            tls.handshakeClientCert()

            # send a packet
            tls.send("GET / HTTP/1.0\n\n\n")

            # try to read some data back
            data = tls.read()
        except (TLSRemoteAlert, socket.error):
            rejected = True
            if args.verbose:
                print("\tBit %d rejected correctly!" % maskBit)
        except (TLSAbruptCloseError, socket.error):
            rejected = True
            if args.verbose:
                print("\tBit %d rejected correctly!" % maskBit)
        if not rejected:
            failBits.append(maskBit)

    if not args.verbose:
        print("")
    if len(failBits) > 0:
        macValidationIssue = getIssueTemplate("MAC_VALIDATION_ERROR")
        macValidationIssue.findings = ', '.join(str(b) for b in failBits)
        report.addIssue(macValidationIssue)
        print("The following modified MAC bits were incorrectly accepted: ", end='')
        print(', '.join(str(b) for b in failBits))
    else:
        print("All modified MAC bits were correctly rejected.")


def testServerRandom():
    """
    Tests if the ServerRandom field is actually random.
    """
    randomData = bytearray(0)
    randomValues = []
    PREFERRED_SAMPLE_SIZE = 1000
    MAX_ITERATIONS = 1200
    count = 0
    
    print("Testing server random values...")

    print("\tGathering data...")
    protocols = filterProtocolsByUserOptions()
    attempts = 0
    while len(serverRandomValues) < PREFERRED_SAMPLE_SIZE and attempts < MAX_ITERATIONS:
        tryConnectionWithCipherSuites( (3,1), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, curves=[c['id'] for c in KnownCurves] )
        tryConnectionWithCipherSuites( (3,2), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, curves=[c['id'] for c in KnownCurves] )
        tryConnectionWithCipherSuites( (3,3), [cipher.ID for cipher in KnownCiphers if cipher.Protocol == ProtocolType.TLS], False, curves=[c['id'] for c in KnownCurves] )
        attempts += 3
    if attempts >= MAX_ITERATIONS:
        print("\tCouldn't collect as much data as we would like to have.")

    # most server random values start with a 4-byte timestamp, so we cut that out
    serverRandomValuesFiltered = []
    for randomValue in serverRandomValues:
        serverRandomValuesFiltered.append(randomValue[4:])

    serverRandomValues.clear()
    serverRandomValues.extend(serverRandomValuesFiltered)

    for randomValue in serverRandomValues:
        randomData.extend(bytearray(randomValue))
    
    print("\tCollected %d bytes of random data." % len(randomData))

    # check for duplicates
    print("\tUniqueness test...")
    uniqueRandoms = set([binascii.hexlify(srv) for srv in serverRandomValues])
    uniqueCount = len(uniqueRandoms)
    sampleCount = len(serverRandomValues)
    if uniqueCount != sampleCount:
        dupeCount = sampleCount - uniqueCount
        # we got more than one value that's the same!?
        print("\t\tDuplicates found! %d samples had %d duplicates." % (sampleCount, dupeCount))
        duplicateRandomIssue = getIssueTemplate("SERVER_RANDOM_DUPLICATE")
        duplicateRandomIssue.findings = ""
    else:
        print("\t\tAll server random values were unique.")

    # check compression
    compressedData = zlib.compress(randomData, 9)
    compressionRatio = (len(compressedData) / float(len(randomData))) * 100.0
    if compressionRatio < 85.0:
        print("\t\tServer random data was compressed to %0.1f%% of its original amount using zlib, potentially indicates low entropy." % compressionRatio)
    else:
        print("\t\tServer random data was not easily compressed (ratio: %0.1f%%), looks high entropy." % compressionRatio)

    # arithmetic mean
    print("\tMean test...")
    mean = sum(float(n) for n in randomData) / len(randomData)
    print("\t\tMean: %f" % mean)
    if abs(mean - 127.5) > 15:
        print("\t\tMean was outside expected range (may indicate poor entropy)")

    # serial correlation
    print("\tSerial correlation test...")
    correlation = 0
    prev = 0
    for n in randomData:
        xor = n ^ prev
        correlation += 1.0 - (float(xor) / 256.0)
        prev = n
    correlation /= len(randomData)
    print("\t\tCorrelation: %f" % correlation)
    if abs(correlation - 0.5) > 0.1:
        print("\t\tSerial correlation was outside expected range (may indicate poor entropy)")

    # monobit frequency
    print("\tMonobit frequency test...")
    bitFreq = 0
    for n in randomData:
        bitFreq += float(bin(n).count("1")) / 8.0
    bitFreq /= len(randomData)
    print("\t\tMonobit frequency: %f" % bitFreq)
    if (abs(bitFreq - 0.5) > 0.1):
        print("\t\tMonobit frequency was outside expected range (may indicate poor entropy)")


# arguments
parser = argparse.ArgumentParser(description="sslxray version " + VERSION)
parser.add_argument("-s", "--host", dest="host", type=str)
parser.add_argument("-S", "--sni", dest="sniName", default=None, type=str)
parser.add_argument("-p", metavar="port", dest="port", type=int, default=443, help="Port to connect to (default: 443)")

parser.add_argument("--list-protocols", dest="listProtocols", action="store_true", default=False, help="List known SSL/TLS protocols.")
parser.add_argument("--list-suites", dest="listSuites", action="store_true", default=False, help="List known SSL/TLS suites.")

parser.add_argument("--disable-protocol", metavar="proto", dest="disabledProtocols", choices=[proto['name'] for proto in KnownProtocols], nargs="+", help="List of protocols to disable in standard enumeration checks. Use --list-protocols for a list of known protocols.")
#parser.add_argument("--timeout", dest="timeout", type=float, default=3.0, help="Socket timeout in seconds (default: 3.0)")

parser.add_argument("-v", dest="verbose", action="store_true", default=False, help="Verbose output")

args = parser.parse_args()

report = None

if __name__ == "__main__":
    if args.listProtocols:
        listProtocols()
    elif args.listSuites:
        listSuites()
    elif args.host is None:
        # no host provided, this is mandatory for all cases except listing!
        parser.print_usage()
    else:
        report = Report()
        print("Scanning %s (%s:%s).  [SNI: %s]" % (args.host, resolveHost(), args.port, args.sniName))
        testCipherSupport()
        testEllipticCurveSupport()
        # we must do the NPN/ALPN reporting after cipher and EC enumeration as the flag is set during these operations
        testNPNSupport()
        testALPNSupport()
        testMACValidation()
        testServerRandom()
        print("Complete.")