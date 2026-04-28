from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.compliance_badge import ComplianceBadge
    from ..models.security_control import SecurityControl
    from ..models.subprocessor_entry import SubprocessorEntry
    from ..models.trust_page_config import TrustPageConfig


T = TypeVar("T", bound="TrustCenterData")


@_attrs_define
class TrustCenterData:
    """Aggregated public trust center page data — NO SECRETS.

    Attributes:
        config (TrustPageConfig): Configuration for a public-facing trust page.
        badges (list[ComplianceBadge] | Unset):
        controls (list[SecurityControl] | Unset):
        subprocessors (list[SubprocessorEntry] | Unset):
        last_updated (str | Unset):
    """

    config: TrustPageConfig
    badges: list[ComplianceBadge] | Unset = UNSET
    controls: list[SecurityControl] | Unset = UNSET
    subprocessors: list[SubprocessorEntry] | Unset = UNSET
    last_updated: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        config = self.config.to_dict()

        badges: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.badges, Unset):
            badges = []
            for badges_item_data in self.badges:
                badges_item = badges_item_data.to_dict()
                badges.append(badges_item)

        controls: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.controls, Unset):
            controls = []
            for controls_item_data in self.controls:
                controls_item = controls_item_data.to_dict()
                controls.append(controls_item)

        subprocessors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.subprocessors, Unset):
            subprocessors = []
            for subprocessors_item_data in self.subprocessors:
                subprocessors_item = subprocessors_item_data.to_dict()
                subprocessors.append(subprocessors_item)

        last_updated = self.last_updated

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "config": config,
            }
        )
        if badges is not UNSET:
            field_dict["badges"] = badges
        if controls is not UNSET:
            field_dict["controls"] = controls
        if subprocessors is not UNSET:
            field_dict["subprocessors"] = subprocessors
        if last_updated is not UNSET:
            field_dict["last_updated"] = last_updated

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.compliance_badge import ComplianceBadge
        from ..models.security_control import SecurityControl
        from ..models.subprocessor_entry import SubprocessorEntry
        from ..models.trust_page_config import TrustPageConfig

        d = dict(src_dict)
        config = TrustPageConfig.from_dict(d.pop("config"))

        _badges = d.pop("badges", UNSET)
        badges: list[ComplianceBadge] | Unset = UNSET
        if _badges is not UNSET:
            badges = []
            for badges_item_data in _badges:
                badges_item = ComplianceBadge.from_dict(badges_item_data)

                badges.append(badges_item)

        _controls = d.pop("controls", UNSET)
        controls: list[SecurityControl] | Unset = UNSET
        if _controls is not UNSET:
            controls = []
            for controls_item_data in _controls:
                controls_item = SecurityControl.from_dict(controls_item_data)

                controls.append(controls_item)

        _subprocessors = d.pop("subprocessors", UNSET)
        subprocessors: list[SubprocessorEntry] | Unset = UNSET
        if _subprocessors is not UNSET:
            subprocessors = []
            for subprocessors_item_data in _subprocessors:
                subprocessors_item = SubprocessorEntry.from_dict(subprocessors_item_data)

                subprocessors.append(subprocessors_item)

        last_updated = d.pop("last_updated", UNSET)

        trust_center_data = cls(
            config=config,
            badges=badges,
            controls=controls,
            subprocessors=subprocessors,
            last_updated=last_updated,
        )

        trust_center_data.additional_properties = d
        return trust_center_data

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
