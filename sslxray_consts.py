
class ProtocolType:
    """
    Protocol type (e.g. SSLv2.0, TLS), used to identify which packet format should be used for a suite.
    """
    SSL = 1,
    SSL2 = 2,
    TLS = 3,
    PCT1_CERT_X509 = 100,
    PCT1_CERT_X509_CHAIN = 101,
    PCT1_HASH_MD5 = 102,
    PCT1_HASH_SHA = 103,
    PCT1_EXCH_RSA_PKCS1 = 104,
    PCT1_CIPHER_RC4 = 105,
    PCT1_ENC_BITS_40 = 106,
    PCT1_ENC_BITS_128 = 107,
    PCT_VERSION_1 = 108

class KeyExchangeType:
    """
    Key exchange type (e.g. RSA, DH), used to provide grouping in cipher suite definitions, to make issue mapping easier.
    """
    NULL = 0
    PSK = 1
    RSA = 2
    RSA_EXPORT = 3
    RSA_EXPORT_1024 = 4
    RSA_FIPS = 5
    DH = 6
    DHE = 7
    ECDH = 8
    ECDHE = 9
    FORTEZZA = 10
    KRB5 = 11
    KRB5_EXPORT = 12
    SRP = 13
    VKO_GOST_R_34_10_94 = 14
    VKO_GOST_R_34_10_2001 = 15
    PCT = 100
    PCT1_MAC_BITS_128 = 101

class AuthenticityType:
    """
    Authenticity type (e.g. RSA, POLY1305), used to provide grouping in cipher suite definitions, to make issue mapping easier.
    """
    NULL = 0,
    RSA = 1,
    RSA_EXPORT = 2,
    RSA_EXPORT_1024 = 3,
    RSA_FIPS = 4,
    DSS = 5,
    ECDSA = 6,
    Anon = 7,
    KRB5 = 8,
    KRB5_EXPORT = 9,
    PSK = 10,
    SHA = 11,
    VKO_GOST_R_34_10_94 = 12
    VKO_GOST_R_34_10_2001 = 13
    KEA = 14
    POLY1305 = 15
    PCT = 100

class EncryptionType:
    """
    Encryption type (e.g. AES128-CBC, RC4), used to provide grouping in cipher suite definitions, to make issue mapping easier.
    """
    NULL = 0
    AES_128_CBC = 10
    AES_128_GCM = 11
    AES_256_CBC = 12
    AES_256_GCM = 13
    RC4_128 = 20
    RC4_128_EXPORT40 = 21
    RC4_40 = 22
    RC4_56 = 23
    RC4_64 = 24
    CAMELLIA_128_CBC = 30
    CAMELLIA_256_CBC = 31
    FORTEZZA_CBC = 40
    GOST28147 = 50
    IDEA_128_CBC = 60
    IDEA_CBC = 61
    RC2_CBC_128_CBC = 70
    RC2_CBC_40 = 71
    RC2_CBC_56 = 72
    SEED_CBC = 80
    TDES_EDE_CBC = 91
    DES_192_EDE3_CBC = 92
    DES_64_CBC = 93
    DES_CBC = 94
    DES_CBC_40 = 95
    DES40_CBC = 96
    CHACHA20 = 100

class MACType:
    """
    Record MAC type (e.g. MD5, SHA256), used to provide grouping in cipher suite definitions, to make issue mapping easier.
    """
    NULL = 0,
    MD5 = 1,
    SHA = 2,
    SHA256 = 3,
    SHA384 = 4,
    SHA512 = 5,
    GOST28147 = 6,
    GOSTR3411 = 7,
    RIPEMD160 = 8
