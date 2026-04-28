from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.gate_evaluate_request_findings_item import GateEvaluateRequestFindingsItem
    from ..models.policy_thresholds import PolicyThresholds


T = TypeVar("T", bound="GateEvaluateRequest")


@_attrs_define
class GateEvaluateRequest:
    """Evaluate findings against a specific policy.

    Attributes:
        findings (list[GateEvaluateRequestFindingsItem]):
        policy_id (None | str | Unset):
        thresholds (None | PolicyThresholds | Unset):
    """

    findings: list[GateEvaluateRequestFindingsItem]
    policy_id: None | str | Unset = UNSET
    thresholds: None | PolicyThresholds | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.policy_thresholds import PolicyThresholds

        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        policy_id: None | str | Unset
        if isinstance(self.policy_id, Unset):
            policy_id = UNSET
        else:
            policy_id = self.policy_id

        thresholds: dict[str, Any] | None | Unset
        if isinstance(self.thresholds, Unset):
            thresholds = UNSET
        elif isinstance(self.thresholds, PolicyThresholds):
            thresholds = self.thresholds.to_dict()
        else:
            thresholds = self.thresholds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if policy_id is not UNSET:
            field_dict["policy_id"] = policy_id
        if thresholds is not UNSET:
            field_dict["thresholds"] = thresholds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.gate_evaluate_request_findings_item import GateEvaluateRequestFindingsItem
        from ..models.policy_thresholds import PolicyThresholds

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = GateEvaluateRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        def _parse_policy_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        policy_id = _parse_policy_id(d.pop("policy_id", UNSET))

        def _parse_thresholds(data: object) -> None | PolicyThresholds | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                thresholds_type_0 = PolicyThresholds.from_dict(data)

                return thresholds_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | PolicyThresholds | Unset, data)

        thresholds = _parse_thresholds(d.pop("thresholds", UNSET))

        gate_evaluate_request = cls(
            findings=findings,
            policy_id=policy_id,
            thresholds=thresholds,
        )

        gate_evaluate_request.additional_properties = d
        return gate_evaluate_request

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
