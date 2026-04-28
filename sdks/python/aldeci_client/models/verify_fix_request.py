from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.verify_fix_request_dep_changes_type_0 import VerifyFixRequestDepChangesType0


T = TypeVar("T", bound="VerifyFixRequest")


@_attrs_define
class VerifyFixRequest:
    """Request body for POST /api/v1/verify/fix.

    Accepts the finding metadata, the original vulnerable code, and the
    proposed fixed code.  language is required; all other fields have
    sensible defaults so callers can omit optional context.

        Attributes:
            original_code (str): The vulnerable code before the fix was applied
            fixed_code (str): The proposed fixed code to verify
            language (str): Source language: python | javascript | typescript | java | go | c | csharp | ruby | php | rust
            finding_id (str | Unset): Identifier of the original finding (e.g. FIND-0042) Default: ''.
            finding_type (str | Unset): Vulnerability category: sql_injection | xss | buffer_overflow | path_traversal |
                command_injection | deserialization | ssrf | open_redirect | xxe | ldap_injection | xpath_injection | ...
                Default: 'unknown'.
            severity (str | Unset): Finding severity: critical | high | medium | low Default: 'high'.
            file_path (None | str | Unset): Optional file path for additional context
            context_code (None | str | Unset): Optional surrounding code for richer analysis
            dep_changes (None | Unset | VerifyFixRequestDepChangesType0): Optional dependency changes {package: new_version}
                introduced by the fix
    """

    original_code: str
    fixed_code: str
    language: str
    finding_id: str | Unset = ""
    finding_type: str | Unset = "unknown"
    severity: str | Unset = "high"
    file_path: None | str | Unset = UNSET
    context_code: None | str | Unset = UNSET
    dep_changes: None | Unset | VerifyFixRequestDepChangesType0 = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.verify_fix_request_dep_changes_type_0 import VerifyFixRequestDepChangesType0

        original_code = self.original_code

        fixed_code = self.fixed_code

        language = self.language

        finding_id = self.finding_id

        finding_type = self.finding_type

        severity = self.severity

        file_path: None | str | Unset
        if isinstance(self.file_path, Unset):
            file_path = UNSET
        else:
            file_path = self.file_path

        context_code: None | str | Unset
        if isinstance(self.context_code, Unset):
            context_code = UNSET
        else:
            context_code = self.context_code

        dep_changes: dict[str, Any] | None | Unset
        if isinstance(self.dep_changes, Unset):
            dep_changes = UNSET
        elif isinstance(self.dep_changes, VerifyFixRequestDepChangesType0):
            dep_changes = self.dep_changes.to_dict()
        else:
            dep_changes = self.dep_changes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "original_code": original_code,
                "fixed_code": fixed_code,
                "language": language,
            }
        )
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if finding_type is not UNSET:
            field_dict["finding_type"] = finding_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if file_path is not UNSET:
            field_dict["file_path"] = file_path
        if context_code is not UNSET:
            field_dict["context_code"] = context_code
        if dep_changes is not UNSET:
            field_dict["dep_changes"] = dep_changes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.verify_fix_request_dep_changes_type_0 import VerifyFixRequestDepChangesType0

        d = dict(src_dict)
        original_code = d.pop("original_code")

        fixed_code = d.pop("fixed_code")

        language = d.pop("language")

        finding_id = d.pop("finding_id", UNSET)

        finding_type = d.pop("finding_type", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_file_path(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        file_path = _parse_file_path(d.pop("file_path", UNSET))

        def _parse_context_code(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        context_code = _parse_context_code(d.pop("context_code", UNSET))

        def _parse_dep_changes(data: object) -> None | Unset | VerifyFixRequestDepChangesType0:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                dep_changes_type_0 = VerifyFixRequestDepChangesType0.from_dict(data)

                return dep_changes_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VerifyFixRequestDepChangesType0, data)

        dep_changes = _parse_dep_changes(d.pop("dep_changes", UNSET))

        verify_fix_request = cls(
            original_code=original_code,
            fixed_code=fixed_code,
            language=language,
            finding_id=finding_id,
            finding_type=finding_type,
            severity=severity,
            file_path=file_path,
            context_code=context_code,
            dep_changes=dep_changes,
        )

        verify_fix_request.additional_properties = d
        return verify_fix_request

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
