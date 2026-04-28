from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.fourth_party_map_dependency_chains_item import FourthPartyMapDependencyChainsItem
    from ..models.fourth_party_map_high_risk_fourth_parties_item import FourthPartyMapHighRiskFourthPartiesItem


T = TypeVar("T", bound="FourthPartyMap")


@_attrs_define
class FourthPartyMap:
    """Complete fourth-party risk map.

    Attributes:
        direct_vendor_count (int | Unset):  Default: 0.
        fourth_party_count (int | Unset):  Default: 0.
        active_transitive_risks (int | Unset):  Default: 0.
        dependency_chains (list[FourthPartyMapDependencyChainsItem] | Unset):
        high_risk_fourth_parties (list[FourthPartyMapHighRiskFourthPartiesItem] | Unset):
    """

    direct_vendor_count: int | Unset = 0
    fourth_party_count: int | Unset = 0
    active_transitive_risks: int | Unset = 0
    dependency_chains: list[FourthPartyMapDependencyChainsItem] | Unset = UNSET
    high_risk_fourth_parties: list[FourthPartyMapHighRiskFourthPartiesItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        direct_vendor_count = self.direct_vendor_count

        fourth_party_count = self.fourth_party_count

        active_transitive_risks = self.active_transitive_risks

        dependency_chains: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.dependency_chains, Unset):
            dependency_chains = []
            for dependency_chains_item_data in self.dependency_chains:
                dependency_chains_item = dependency_chains_item_data.to_dict()
                dependency_chains.append(dependency_chains_item)

        high_risk_fourth_parties: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.high_risk_fourth_parties, Unset):
            high_risk_fourth_parties = []
            for high_risk_fourth_parties_item_data in self.high_risk_fourth_parties:
                high_risk_fourth_parties_item = high_risk_fourth_parties_item_data.to_dict()
                high_risk_fourth_parties.append(high_risk_fourth_parties_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if direct_vendor_count is not UNSET:
            field_dict["direct_vendor_count"] = direct_vendor_count
        if fourth_party_count is not UNSET:
            field_dict["fourth_party_count"] = fourth_party_count
        if active_transitive_risks is not UNSET:
            field_dict["active_transitive_risks"] = active_transitive_risks
        if dependency_chains is not UNSET:
            field_dict["dependency_chains"] = dependency_chains
        if high_risk_fourth_parties is not UNSET:
            field_dict["high_risk_fourth_parties"] = high_risk_fourth_parties

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fourth_party_map_dependency_chains_item import FourthPartyMapDependencyChainsItem
        from ..models.fourth_party_map_high_risk_fourth_parties_item import FourthPartyMapHighRiskFourthPartiesItem

        d = dict(src_dict)
        direct_vendor_count = d.pop("direct_vendor_count", UNSET)

        fourth_party_count = d.pop("fourth_party_count", UNSET)

        active_transitive_risks = d.pop("active_transitive_risks", UNSET)

        _dependency_chains = d.pop("dependency_chains", UNSET)
        dependency_chains: list[FourthPartyMapDependencyChainsItem] | Unset = UNSET
        if _dependency_chains is not UNSET:
            dependency_chains = []
            for dependency_chains_item_data in _dependency_chains:
                dependency_chains_item = FourthPartyMapDependencyChainsItem.from_dict(dependency_chains_item_data)

                dependency_chains.append(dependency_chains_item)

        _high_risk_fourth_parties = d.pop("high_risk_fourth_parties", UNSET)
        high_risk_fourth_parties: list[FourthPartyMapHighRiskFourthPartiesItem] | Unset = UNSET
        if _high_risk_fourth_parties is not UNSET:
            high_risk_fourth_parties = []
            for high_risk_fourth_parties_item_data in _high_risk_fourth_parties:
                high_risk_fourth_parties_item = FourthPartyMapHighRiskFourthPartiesItem.from_dict(
                    high_risk_fourth_parties_item_data
                )

                high_risk_fourth_parties.append(high_risk_fourth_parties_item)

        fourth_party_map = cls(
            direct_vendor_count=direct_vendor_count,
            fourth_party_count=fourth_party_count,
            active_transitive_risks=active_transitive_risks,
            dependency_chains=dependency_chains,
            high_risk_fourth_parties=high_risk_fourth_parties,
        )

        fourth_party_map.additional_properties = d
        return fourth_party_map

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
