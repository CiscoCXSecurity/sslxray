
class ALPNProtocolInfo:
    """
    ALPN Protocol Info class. Stores information about each ALPN protocol.
    """
    Name = ""
    Outdated = False

    Issues = []

    def __init__(self, name="", outdated=False):
        self.Name = name
        self.Outdated = outdated
