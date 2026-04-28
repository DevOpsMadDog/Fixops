from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PublishDSLIn")


@_attrs_define
class PublishDSLIn:
    """
    Attributes:
        key (str): Stable rule key (matched against DSL `key`)
        dsl_text (str): Raw YAML or JSON rule text
        dsl_format (str | Unset): 'yaml' or 'json' Default: 'yaml'.
        severity (None | str | Unset): Override severity; defaults to the DSL value.
        authored_by (str | Unset): User/service that authored the rule Default: ''.
    """

    key: str
    dsl_text: str
    dsl_format: str | Unset = "yaml"
    severity: None | str | Unset = UNSET
    authored_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        key = self.key

        dsl_text = self.dsl_text

        dsl_format = self.dsl_format

        severity: None | str | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        else:
            severity = self.severity

        authored_by = self.authored_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "key": key,
                "dsl_text": dsl_text,
            }
        )
        if dsl_format is not UNSET:
            field_dict["dsl_format"] = dsl_format
        if severity is not UNSET:
            field_dict["severity"] = severity
        if authored_by is not UNSET:
            field_dict["authored_by"] = authored_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        key = d.pop("key")

        dsl_text = d.pop("dsl_text")

        dsl_format = d.pop("dsl_format", UNSET)

        def _parse_severity(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        authored_by = d.pop("authored_by", UNSET)

        publish_dsl_in = cls(
            key=key,
            dsl_text=dsl_text,
            dsl_format=dsl_format,
            severity=severity,
            authored_by=authored_by,
        )

        publish_dsl_in.additional_properties = d
        return publish_dsl_in

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
