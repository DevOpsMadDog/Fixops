from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TestRun")


@_attrs_define
class TestRun:
    """
    Attributes:
        org_id (str):
        test_name (str):
        test_method (str | Unset):  Default: 'manual'.
        tester (str | Unset):  Default: ''.
        result (str | Unset):  Default: 'fail'.
        score (float | Unset):  Default: 0.0.
        findings (str | Unset):  Default: ''.
        evidence (str | Unset):  Default: ''.
    """

    org_id: str
    test_name: str
    test_method: str | Unset = "manual"
    tester: str | Unset = ""
    result: str | Unset = "fail"
    score: float | Unset = 0.0
    findings: str | Unset = ""
    evidence: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        test_name = self.test_name

        test_method = self.test_method

        tester = self.tester

        result = self.result

        score = self.score

        findings = self.findings

        evidence = self.evidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "test_name": test_name,
            }
        )
        if test_method is not UNSET:
            field_dict["test_method"] = test_method
        if tester is not UNSET:
            field_dict["tester"] = tester
        if result is not UNSET:
            field_dict["result"] = result
        if score is not UNSET:
            field_dict["score"] = score
        if findings is not UNSET:
            field_dict["findings"] = findings
        if evidence is not UNSET:
            field_dict["evidence"] = evidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        test_name = d.pop("test_name")

        test_method = d.pop("test_method", UNSET)

        tester = d.pop("tester", UNSET)

        result = d.pop("result", UNSET)

        score = d.pop("score", UNSET)

        findings = d.pop("findings", UNSET)

        evidence = d.pop("evidence", UNSET)

        test_run = cls(
            org_id=org_id,
            test_name=test_name,
            test_method=test_method,
            tester=tester,
            result=result,
            score=score,
            findings=findings,
            evidence=evidence,
        )

        test_run.additional_properties = d
        return test_run

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
