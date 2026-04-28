from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RemediationPlaybook")


@_attrs_define
class RemediationPlaybook:
    """
    Attributes:
        finding_id (str):
        rule_id (str):
        title (str):
        steps (list[str]):
        cli_commands (list[str] | Unset):
        terraform_blocks (list[str] | Unset):
        estimated_effort (str | Unset):  Default: '5 minutes'.
        risk_level (str | Unset):  Default: 'low'.
        requires_downtime (bool | Unset):  Default: False.
    """

    finding_id: str
    rule_id: str
    title: str
    steps: list[str]
    cli_commands: list[str] | Unset = UNSET
    terraform_blocks: list[str] | Unset = UNSET
    estimated_effort: str | Unset = "5 minutes"
    risk_level: str | Unset = "low"
    requires_downtime: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        rule_id = self.rule_id

        title = self.title

        steps = self.steps

        cli_commands: list[str] | Unset = UNSET
        if not isinstance(self.cli_commands, Unset):
            cli_commands = self.cli_commands

        terraform_blocks: list[str] | Unset = UNSET
        if not isinstance(self.terraform_blocks, Unset):
            terraform_blocks = self.terraform_blocks

        estimated_effort = self.estimated_effort

        risk_level = self.risk_level

        requires_downtime = self.requires_downtime

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "rule_id": rule_id,
                "title": title,
                "steps": steps,
            }
        )
        if cli_commands is not UNSET:
            field_dict["cli_commands"] = cli_commands
        if terraform_blocks is not UNSET:
            field_dict["terraform_blocks"] = terraform_blocks
        if estimated_effort is not UNSET:
            field_dict["estimated_effort"] = estimated_effort
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if requires_downtime is not UNSET:
            field_dict["requires_downtime"] = requires_downtime

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        rule_id = d.pop("rule_id")

        title = d.pop("title")

        steps = cast(list[str], d.pop("steps"))

        cli_commands = cast(list[str], d.pop("cli_commands", UNSET))

        terraform_blocks = cast(list[str], d.pop("terraform_blocks", UNSET))

        estimated_effort = d.pop("estimated_effort", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        requires_downtime = d.pop("requires_downtime", UNSET)

        remediation_playbook = cls(
            finding_id=finding_id,
            rule_id=rule_id,
            title=title,
            steps=steps,
            cli_commands=cli_commands,
            terraform_blocks=terraform_blocks,
            estimated_effort=estimated_effort,
            risk_level=risk_level,
            requires_downtime=requires_downtime,
        )

        remediation_playbook.additional_properties = d
        return remediation_playbook

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
