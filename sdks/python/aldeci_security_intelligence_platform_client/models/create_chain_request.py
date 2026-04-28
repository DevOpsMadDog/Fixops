from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateChainRequest")


@_attrs_define
class CreateChainRequest:
    """
    Attributes:
        chain_name (str): Name of the attack chain
        org_id (str | Unset):  Default: 'default'.
        threat_actor (str | Unset): Threat actor attribution Default: ''.
        kill_chain_phase (str | Unset):
            reconnaissance/weaponization/delivery/exploitation/installation/c2/actions_on_objectives Default:
            'reconnaissance'.
        confidence (float | Unset):  Default: 50.0.
        iocs (list[str] | Unset): Indicators of compromise
    """

    chain_name: str
    org_id: str | Unset = "default"
    threat_actor: str | Unset = ""
    kill_chain_phase: str | Unset = "reconnaissance"
    confidence: float | Unset = 50.0
    iocs: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        chain_name = self.chain_name

        org_id = self.org_id

        threat_actor = self.threat_actor

        kill_chain_phase = self.kill_chain_phase

        confidence = self.confidence

        iocs: list[str] | Unset = UNSET
        if not isinstance(self.iocs, Unset):
            iocs = self.iocs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "chain_name": chain_name,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if threat_actor is not UNSET:
            field_dict["threat_actor"] = threat_actor
        if kill_chain_phase is not UNSET:
            field_dict["kill_chain_phase"] = kill_chain_phase
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if iocs is not UNSET:
            field_dict["iocs"] = iocs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        chain_name = d.pop("chain_name")

        org_id = d.pop("org_id", UNSET)

        threat_actor = d.pop("threat_actor", UNSET)

        kill_chain_phase = d.pop("kill_chain_phase", UNSET)

        confidence = d.pop("confidence", UNSET)

        iocs = cast(list[str], d.pop("iocs", UNSET))

        create_chain_request = cls(
            chain_name=chain_name,
            org_id=org_id,
            threat_actor=threat_actor,
            kill_chain_phase=kill_chain_phase,
            confidence=confidence,
            iocs=iocs,
        )

        create_chain_request.additional_properties = d
        return create_chain_request

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
