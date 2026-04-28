from enum import Enum


class ThreatCategory(str, Enum):
    CMDI = "cmdi"
    LFI = "lfi"
    PATH_TRAVERSAL = "path_traversal"
    RFI = "rfi"
    SQLI = "sqli"
    SSRF = "ssrf"
    XSS = "xss"
    XXE = "xxe"

    def __str__(self) -> str:
        return str(self.value)
