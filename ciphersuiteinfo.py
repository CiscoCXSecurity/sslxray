
class CipherSuiteInfo:
    """
    Cipher suite info class. Stores information about each cipher suite, such as its identifier, name, and minimum protocol version.
    """
    ID = 0
    Name = ""
    Protocol = None
    KeyExchange = None
    Authenticity = None
    Encryption = None
    Bits = 0
    MAC = None

    Issues = []

    def __init__(self, name="", id=0, protocol=None, keyExchange=None, authenticity=None, encryption=None, bits=0, mac=None):
        self.Name = name
        self.ID = id
        self.Protocol = protocol
        self.KeyExchange = keyExchange
        self.Authenticity = authenticity
        self.Encryption = encryption
        self.Bits = bits
        self.MAC = mac
