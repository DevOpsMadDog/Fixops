from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sbom_component import SBOMComponent


T = TypeVar("T", bound="SBOMAuditRequest")


@_attrs_define
class SBOMAuditRequest:
    """Request body for SBOM compliance audit.

    Attributes:
        components (list[SBOMComponent]):
        policy_id (str | Unset): Policy to apply Default: 'default-commercial'.
        report_id (None | str | Unset): Optional report ID
    """

    components: list[SBOMComponent]
    policy_id: str | Unset = "default-commercial"
    report_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        components = []
        for components_item_data in self.components:
            components_item = components_item_data.to_dict()
            components.append(components_item)

        policy_id = self.policy_id

        report_id: None | str | Unset
        if isinstance(self.report_id, Unset):
            report_id = UNSET
        else:
            report_id = self.report_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "components": components,
            }
        )
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if report_id is not UNSET:
            field_dict["report_id"] = report_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sbom_component import SBOMComponent

        d = dict(src_dict)
        components = []
        _components = d.pop("components")
        for components_item_data in _components:
            components_item = SBOMComponent.from_dict(components_item_data)

            components.append(components_item)

        policy_id = d.pop("policy_id", UNSET)

        def _parse_report_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        report_id = _parse_report_id(d.pop("report_id", UNSET))

        sbom_audit_request = cls(
            components=components,
            policy_id=policy_id,
            report_id=report_id,
        )

        sbom_audit_request.additional_properties = d
        return sbom_audit_request

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
