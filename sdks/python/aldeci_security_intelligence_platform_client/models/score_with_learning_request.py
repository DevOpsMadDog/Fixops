from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScoreWithLearningRequest")


@_attrs_define
class ScoreWithLearningRequest:
    """
    Attributes:
        cvss_score (float | Unset): CVSS base score Default: 7.5.
        epss_score (float | Unset): EPSS probability Default: 0.3.
        in_kev (bool | Unset): In CISA KEV catalog? Default: False.
        asset_criticality (float | Unset): Asset criticality Default: 0.7.
        scanner (str | Unset): Scanner that found this Default: 'semgrep'.
        rule_id (str | Unset): Rule/check ID Default: 'CWE-89-sql-injection'.
        fix_type (str | Unset): Expected fix type Default: 'CODE_PATCH'.
    """

    cvss_score: float | Unset = 7.5
    epss_score: float | Unset = 0.3
    in_kev: bool | Unset = False
    asset_criticality: float | Unset = 0.7
    scanner: str | Unset = "semgrep"
    rule_id: str | Unset = "CWE-89-sql-injection"
    fix_type: str | Unset = "CODE_PATCH"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cvss_score = self.cvss_score

        epss_score = self.epss_score

        in_kev = self.in_kev

        asset_criticality = self.asset_criticality

        scanner = self.scanner

        rule_id = self.rule_id

        fix_type = self.fix_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cvss_score is not UNSET:
            field_dict["cvss_score"] = cvss_score
        if epss_score is not UNSET:
            field_dict["epss_score"] = epss_score
        if in_kev is not UNSET:
            field_dict["in_kev"] = in_kev
        if asset_criticality is not UNSET:
            field_dict["asset_criticality"] = asset_criticality
        if scanner is not UNSET:
            field_dict["scanner"] = scanner
        if rule_id is not UNSET:
            field_dict["rule_id"] = rule_id
        if fix_type is not UNSET:
            field_dict["fix_type"] = fix_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cvss_score = d.pop("cvss_score", UNSET)

        epss_score = d.pop("epss_score", UNSET)

        in_kev = d.pop("in_kev", UNSET)

        asset_criticality = d.pop("asset_criticality", UNSET)

        scanner = d.pop("scanner", UNSET)

        rule_id = d.pop("rule_id", UNSET)

        fix_type = d.pop("fix_type", UNSET)

        score_with_learning_request = cls(
            cvss_score=cvss_score,
            epss_score=epss_score,
            in_kev=in_kev,
            asset_criticality=asset_criticality,
            scanner=scanner,
            rule_id=rule_id,
            fix_type=fix_type,
        )

        score_with_learning_request.additional_properties = d
        return score_with_learning_request

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
