from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BlueTeamActionRequest")


@_attrs_define
class BlueTeamActionRequest:
    """
    Attributes:
        step_index (int): Zero-based index of the step being responded to
        action (str): Containment action: isolate_host, block_ip, disable_account, revoke_token, quarantine_file,
            firewall_rule, patch_applied, escalate, monitor
        actor (str | Unset): Who performed the action Default: 'blue_team'.
        description (str | Unset): Action details Default: ''.
        effective (bool | Unset): Was the action effective? Default: True.
    """

    step_index: int
    action: str
    actor: str | Unset = "blue_team"
    description: str | Unset = ""
    effective: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        step_index = self.step_index

        action = self.action

        actor = self.actor

        description = self.description

        effective = self.effective

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "step_index": step_index,
                "action": action,
            }
        )
        if actor is not UNSET:
            field_dict["actor"] = actor
        if description is not UNSET:
            field_dict["description"] = description
        if effective is not UNSET:
            field_dict["effective"] = effective

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        step_index = d.pop("step_index")

        action = d.pop("action")

        actor = d.pop("actor", UNSET)

        description = d.pop("description", UNSET)

        effective = d.pop("effective", UNSET)

        blue_team_action_request = cls(
            step_index=step_index,
            action=action,
            actor=actor,
            description=description,
            effective=effective,
        )

        blue_team_action_request.additional_properties = d
        return blue_team_action_request

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
