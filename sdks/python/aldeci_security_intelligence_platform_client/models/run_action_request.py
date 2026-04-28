from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.run_action_request_finding import RunActionRequestFinding


T = TypeVar("T", bound="RunActionRequest")


@_attrs_define
class RunActionRequest:
    """
    Attributes:
        finding (RunActionRequestFinding):
        org_id (str | Unset):  Default: 'default'.
    """

    finding: RunActionRequestFinding
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.run_action_request_finding import RunActionRequestFinding

        d = dict(src_dict)
        finding = RunActionRequestFinding.from_dict(d.pop("finding"))

        org_id = d.pop("org_id", UNSET)

        run_action_request = cls(
            finding=finding,
            org_id=org_id,
        )

        run_action_request.additional_properties = d
        return run_action_request

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
