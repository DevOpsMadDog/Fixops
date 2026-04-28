from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.auto_merge_check_request_finding_type_0 import AutoMergeCheckRequestFindingType0


T = TypeVar("T", bound="AutoMergeCheckRequest")


@_attrs_define
class AutoMergeCheckRequest:
    """Request to check if a fix qualifies for auto-merge.

    Attributes:
        fix_id (str): ID of the fix to check
        finding (AutoMergeCheckRequestFindingType0 | None | Unset): Original finding (for context enrichment)
    """

    fix_id: str
    finding: AutoMergeCheckRequestFindingType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.auto_merge_check_request_finding_type_0 import AutoMergeCheckRequestFindingType0

        fix_id = self.fix_id

        finding: dict[str, Any] | None | Unset
        if isinstance(self.finding, Unset):
            finding = UNSET
        elif isinstance(self.finding, AutoMergeCheckRequestFindingType0):
            finding = self.finding.to_dict()
        else:
            finding = self.finding

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "fix_id": fix_id,
            }
        )
        if finding is not UNSET:
            field_dict["finding"] = finding

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.auto_merge_check_request_finding_type_0 import AutoMergeCheckRequestFindingType0

        d = dict(src_dict)
        fix_id = d.pop("fix_id")

        def _parse_finding(data: object) -> AutoMergeCheckRequestFindingType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                finding_type_0 = AutoMergeCheckRequestFindingType0.from_dict(data)

                return finding_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AutoMergeCheckRequestFindingType0 | None | Unset, data)

        finding = _parse_finding(d.pop("finding", UNSET))

        auto_merge_check_request = cls(
            fix_id=fix_id,
            finding=finding,
        )

        auto_merge_check_request.additional_properties = d
        return auto_merge_check_request

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
