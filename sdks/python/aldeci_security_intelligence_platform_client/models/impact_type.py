from enum import Enum


class ImpactType(str, Enum):
    AUTHENTICATION_BYPASS = "authentication_bypass"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    DENIAL_OF_SERVICE = "denial_of_service"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INSECURE_DIRECT_OBJECT_REFERENCE = "insecure_direct_object_reference"
    OTHER = "other"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    SERVER_SIDE_REQUEST_FORGERY = "server_side_request_forgery"
    SQL_INJECTION = "sql_injection"
    XML_EXTERNAL_ENTITY = "xml_external_entity"

    def __str__(self) -> str:
        return str(self.value)
