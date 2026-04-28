from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScenarioCreate")


@_attrs_define
class ScenarioCreate:
    """
    Attributes:
        scenario_name (str): Scenario name
        asset_name (str): Asset under threat
        threat_actor (str): Threat actor description
        threat_type (str | Unset):
            malware/ransomware/insider/ddos/phishing/supply_chain/physical/natural_disaster/system_failure Default:
            'malware'.
        asset_value (float | Unset): Asset value in $ Default: 0.0.
        exposure_factor (float | Unset): Exposure factor 0.0-1.0 Default: 0.5.
        annual_rate_occurrence (float | Unset): Expected occurrences per year Default: 1.0.
    """

    scenario_name: str
    asset_name: str
    threat_actor: str
    threat_type: str | Unset = "malware"
    asset_value: float | Unset = 0.0
    exposure_factor: float | Unset = 0.5
    annual_rate_occurrence: float | Unset = 1.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scenario_name = self.scenario_name

        asset_name = self.asset_name

        threat_actor = self.threat_actor

        threat_type = self.threat_type

        asset_value = self.asset_value

        exposure_factor = self.exposure_factor

        annual_rate_occurrence = self.annual_rate_occurrence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scenario_name": scenario_name,
                "asset_name": asset_name,
                "threat_actor": threat_actor,
            }
        )
        if threat_type is not UNSET:
            field_dict["threat_type"] = threat_type
        if asset_value is not UNSET:
            field_dict["asset_value"] = asset_value
        if exposure_factor is not UNSET:
            field_dict["exposure_factor"] = exposure_factor
        if annual_rate_occurrence is not UNSET:
            field_dict["annual_rate_occurrence"] = annual_rate_occurrence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scenario_name = d.pop("scenario_name")

        asset_name = d.pop("asset_name")

        threat_actor = d.pop("threat_actor")

        threat_type = d.pop("threat_type", UNSET)

        asset_value = d.pop("asset_value", UNSET)

        exposure_factor = d.pop("exposure_factor", UNSET)

        annual_rate_occurrence = d.pop("annual_rate_occurrence", UNSET)

        scenario_create = cls(
            scenario_name=scenario_name,
            asset_name=asset_name,
            threat_actor=threat_actor,
            threat_type=threat_type,
            asset_value=asset_value,
            exposure_factor=exposure_factor,
            annual_rate_occurrence=annual_rate_occurrence,
        )

        scenario_create.additional_properties = d
        return scenario_create

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
