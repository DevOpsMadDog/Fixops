from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.weights_update_request_weights import WeightsUpdateRequestWeights


T = TypeVar("T", bound="WeightsUpdateRequest")


@_attrs_define
class WeightsUpdateRequest:
    """New weights for one or more factors.

    Attributes:
        weights (WeightsUpdateRequestWeights): Factor → weight mapping. Known factors: cvss_score, epss_score,
            asset_criticality, exposure_level, exploit_available, age_days, has_patch, in_attack_path
    """

    weights: WeightsUpdateRequestWeights
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        weights = self.weights.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "weights": weights,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.weights_update_request_weights import WeightsUpdateRequestWeights

        d = dict(src_dict)
        weights = WeightsUpdateRequestWeights.from_dict(d.pop("weights"))

        weights_update_request = cls(
            weights=weights,
        )

        weights_update_request.additional_properties = d
        return weights_update_request

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
