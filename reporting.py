
class Report:
    def __init__(self):
        self.ref = ""
        self.date = None
        self.targethost = ""
        self.targetport = 0
        self.issues = []

    def __len__(self):
        return len(self.issues)

    def addIssue(self, issue):
        self.issues.append(issue)

    def findByRef(self, ref):
        return [i for i in self.issues if i.ref == ref]


STCA_REPORT_TYPE_ISSUE = 1
STCA_REPORT_TYPE_INFO = 2

class Issue:
    def __init__(self, ref, type, message):
        self.ref = ref
        self.type = type
        self.message = message
        self.findings = ""
        self.findingTemplate = None

    def __str__(self):
        return self.message + "\r\n" + self.findings
