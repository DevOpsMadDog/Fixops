from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.bayesian_update_request_components_item import BayesianUpdateRequestComponentsItem
    from ..models.bayesian_update_request_network import BayesianUpdateRequestNetwork


T = TypeVar("T", bound="BayesianUpdateRequest")


@_attrs_define
class BayesianUpdateRequest:
    """Request for Bayesian probability update.

    Attributes:
        components (list[BayesianUpdateRequestComponentsItem]): Component definitions with optional observed states
        network (BayesianUpdateRequestNetwork): Bayesian network definition with nodes and CPTs
    """

    components: list[BayesianUpdateRequestComponentsItem]
    network: BayesianUpdateRequestNetwork
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        components = []
        for components_item_data in self.components:
            components_item = components_item_data.to_dict()
            components.append(components_item)

        network = self.network.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "components": components,
                "network": network,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bayesian_update_request_components_item import BayesianUpdateRequestComponentsItem
        from ..models.bayesian_update_request_network import BayesianUpdateRequestNetwork

        d = dict(src_dict)
        components = []
        _components = d.pop("components")
        for components_item_data in _components:
            components_item = BayesianUpdateRequestComponentsItem.from_dict(components_item_data)

            components.append(components_item)

        network = BayesianUpdateRequestNetwork.from_dict(d.pop("network"))

        bayesian_update_request = cls(
            components=components,
            network=network,
        )

        bayesian_update_request.additional_properties = d
        return bayesian_update_request

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
