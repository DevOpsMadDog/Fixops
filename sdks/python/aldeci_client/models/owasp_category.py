from enum import Enum


class OWASPCategory(str, Enum):
    A012021_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A022021_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A032021_INJECTION = "A03:2021-Injection"
    A042021_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A052021_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A062021_VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A072021_IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021-Identification and Authentication Failures"
    A082021_SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021-Software and Data Integrity Failures"
    A092021_SECURITY_LOGGING_AND_MONITORING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A102021_SERVER_SIDE_REQUEST_FORGERY = "A10:2021-Server-Side Request Forgery"
    OTHER = "Other"

    def __str__(self) -> str:
        return str(self.value)
