from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScenarioUpdate")


@_attrs_define
class ScenarioUpdate:
    """
    Attributes:
        name (None | str | Unset):
        threat_actor (None | str | Unset):
        attack_vector (None | str | Unset):
        target_asset_type (None | str | Unset):
        likelihood_pct (float | None | Unset):
        minimum_loss (float | None | Unset):
        maximum_loss (float | None | Unset):
    """

    name: None | str | Unset = UNSET
    threat_actor: None | str | Unset = UNSET
    attack_vector: None | str | Unset = UNSET
    target_asset_type: None | str | Unset = UNSET
    likelihood_pct: float | None | Unset = UNSET
    minimum_loss: float | None | Unset = UNSET
    maximum_loss: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        threat_actor: None | str | Unset
        if isinstance(self.threat_actor, Unset):
            threat_actor = UNSET
        else:
            threat_actor = self.threat_actor

        attack_vector: None | str | Unset
        if isinstance(self.attack_vector, Unset):
            attack_vector = UNSET
        else:
            attack_vector = self.attack_vector

        target_asset_type: None | str | Unset
        if isinstance(self.target_asset_type, Unset):
            target_asset_type = UNSET
        else:
            target_asset_type = self.target_asset_type

        likelihood_pct: float | None | Unset
        if isinstance(self.likelihood_pct, Unset):
            likelihood_pct = UNSET
        else:
            likelihood_pct = self.likelihood_pct

        minimum_loss: float | None | Unset
        if isinstance(self.minimum_loss, Unset):
            minimum_loss = UNSET
        else:
            minimum_loss = self.minimum_loss

        maximum_loss: float | None | Unset
        if isinstance(self.maximum_loss, Unset):
            maximum_loss = UNSET
        else:
            maximum_loss = self.maximum_loss

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if attack_vector is not UNSET:
            field_dict["attack_vector"] = attack_vector
        if target_asset_type is not UNSET:
            field_dict["target_asset_type"] = target_asset_type
        if likelihood_pct is not UNSET:
            field_dict["likelihood_pct"] = likelihood_pct
        if minimum_loss is not UNSET:
            field_dict["minimum_loss"] = minimum_loss
        if maximum_loss is not UNSET:
            field_dict["maximum_loss"] = maximum_loss

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_threat_actor(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        threat_actor = _parse_threat_actor(d.pop("threat_actor", UNSET))

        def _parse_attack_vector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attack_vector = _parse_attack_vector(d.pop("attack_vector", UNSET))

        def _parse_target_asset_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_asset_type = _parse_target_asset_type(d.pop("target_asset_type", UNSET))

        def _parse_likelihood_pct(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        likelihood_pct = _parse_likelihood_pct(d.pop("likelihood_pct", UNSET))

        def _parse_minimum_loss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        minimum_loss = _parse_minimum_loss(d.pop("minimum_loss", UNSET))

        def _parse_maximum_loss(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        maximum_loss = _parse_maximum_loss(d.pop("maximum_loss", UNSET))

        scenario_update = cls(
            name=name,
            threat_actor=threat_actor,
            attack_vector=attack_vector,
            target_asset_type=target_asset_type,
            likelihood_pct=likelihood_pct,
            minimum_loss=minimum_loss,
            maximum_loss=maximum_loss,
        )

        scenario_update.additional_properties = d
        return scenario_update

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
