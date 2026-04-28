from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PlaybookRequest")


@_attrs_define
class PlaybookRequest:
    """Request to generate remediation playbook.

    Attributes:
        finding_ids (list[str]):
        audience (str | Unset): developer, devops, security Default: 'developer'.
        include_rollback (bool | Unset):  Default: True.
    """

    finding_ids: list[str]
    audience: str | Unset = "developer"
    include_rollback: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_ids = self.finding_ids

        audience = self.audience

        include_rollback = self.include_rollback

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_ids": finding_ids,
            }
        )
        if audience is not UNSET:
            field_dict["audience"] = audience
        if include_rollback is not UNSET:
            field_dict["include_rollback"] = include_rollback

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_ids = cast(list[str], d.pop("finding_ids"))

        audience = d.pop("audience", UNSET)

        include_rollback = d.pop("include_rollback", UNSET)

        playbook_request = cls(
            finding_ids=finding_ids,
            audience=audience,
            include_rollback=include_rollback,
        )

        playbook_request.additional_properties = d
        return playbook_request

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
