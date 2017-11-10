from reporting import *

IssueTemplates = [
    Issue("CIPHERS_SUPPORTED",                  STCA_REPORT_TYPE_INFO,  "The following cipher suites were found to be enabled:"),
    Issue("WEAK_CIPHER_KEY_SIZE",               STCA_REPORT_TYPE_ISSUE, "Cipher suites with weak key sizes (i.e. less than 128-bit) were found to be enabled."),
    Issue("SSL2_SUPPORTED",                     STCA_REPORT_TYPE_ISSUE, "The SSL version 2 protocol was found to be accepted by the server."),
    Issue("SSL3_SUPPORTED",                     STCA_REPORT_TYPE_ISSUE, "The SSL version 3 protocol was found to be accepted by the server."),
    Issue("SERVER_RANDOM_DUPLICATES",           STCA_REPORT_TYPE_ISSUE, "The SSL/TLS implementation on the server was found to send duplicate ServerRandom values between connections."),
    Issue("MAC_VALIDATION_ERROR",               STCA_REPORT_TYPE_ISSUE, "The server did not properly validate the following bits:"),
]

# check that there aren't any issues with duplicate template IDs
duperefs = set([t.ref for t in IssueTemplates if IssueTemplates.count(t.ref) > 1])
if len(duperefs) > 0:
    raise RuntimeError("Duplicate index in IssueTemplates (" + duperefs[0] + ")")

def getIssueTemplate(ref):
    issues = [t for t in IssueTemplates if t.ref == ref]
    assert len(issues) <= 1
    if len(issues) < 1:
        return None
    return issues[0]
