from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreatePlaybookBody")


@_attrs_define
class CreatePlaybookBody:
    """
    Attributes:
        playbook_name (str): Name of the hunting playbook
        hunt_type (str): hypothesis | ioc | anomaly | behavioral | threat-actor | ttp | situational
        threat_category (str): Threat category being hunted
        mitre_technique (str | Unset): MITRE ATT&CK technique ID Default: ''.
        hypothesis (str | Unset): Primary hunt hypothesis Default: ''.
        data_sources (list[str] | None | Unset): Data sources required
        tools (list[str] | None | Unset): Tools used in this hunt
    """

    playbook_name: str
    hunt_type: str
    threat_category: str
    mitre_technique: str | Unset = ""
    hypothesis: str | Unset = ""
    data_sources: list[str] | None | Unset = UNSET
    tools: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        playbook_name = self.playbook_name

        hunt_type = self.hunt_type

        threat_category = self.threat_category

        mitre_technique = self.mitre_technique

        hypothesis = self.hypothesis

        data_sources: list[str] | None | Unset
        if isinstance(self.data_sources, Unset):
            data_sources = UNSET
        elif isinstance(self.data_sources, list):
            data_sources = self.data_sources

        else:
            data_sources = self.data_sources

        tools: list[str] | None | Unset
        if isinstance(self.tools, Unset):
            tools = UNSET
        elif isinstance(self.tools, list):
            tools = self.tools

        else:
            tools = self.tools

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "playbook_name": playbook_name,
                "hunt_type": hunt_type,
                "threat_category": threat_category,
            }
        )
        if mitre_technique is not UNSET:
            field_dict["mitre_technique"] = mitre_technique
        if hypothesis is not UNSET:
            field_dict["hypothesis"] = hypothesis
        if data_sources is not UNSET:
            field_dict["data_sources"] = data_sources
        if tools is not UNSET:
            field_dict["tools"] = tools

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        playbook_name = d.pop("playbook_name")

        hunt_type = d.pop("hunt_type")

        threat_category = d.pop("threat_category")

        mitre_technique = d.pop("mitre_technique", UNSET)

        hypothesis = d.pop("hypothesis", UNSET)

        def _parse_data_sources(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                data_sources_type_0 = cast(list[str], data)

                return data_sources_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        data_sources = _parse_data_sources(d.pop("data_sources", UNSET))

        def _parse_tools(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                tools_type_0 = cast(list[str], data)

                return tools_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        tools = _parse_tools(d.pop("tools", UNSET))

        create_playbook_body = cls(
            playbook_name=playbook_name,
            hunt_type=hunt_type,
            threat_category=threat_category,
            mitre_technique=mitre_technique,
            hypothesis=hypothesis,
            data_sources=data_sources,
            tools=tools,
        )

        create_playbook_body.additional_properties = d
        return create_playbook_body

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
