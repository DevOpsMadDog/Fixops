from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.check_create import CheckCreate


T = TypeVar("T", bound="BulkChecksCreate")


@_attrs_define
class BulkChecksCreate:
    """
    Attributes:
        checks (list[CheckCreate]):
    """

    checks: list[CheckCreate]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        checks = []
        for checks_item_data in self.checks:
            checks_item = checks_item_data.to_dict()
            checks.append(checks_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "checks": checks,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.check_create import CheckCreate

        d = dict(src_dict)
        checks = []
        _checks = d.pop("checks")
        for checks_item_data in _checks:
            checks_item = CheckCreate.from_dict(checks_item_data)

            checks.append(checks_item)

        bulk_checks_create = cls(
            checks=checks,
        )

        bulk_checks_create.additional_properties = d
        return bulk_checks_create

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
