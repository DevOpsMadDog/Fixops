from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BenchmarkIn")


@_attrs_define
class BenchmarkIn:
    """
    Attributes:
        account_id (str):
        benchmark (str | Unset):  Default: 'cis_aws_v1.5'.
        pass_count (int | Unset):  Default: 0.
        fail_count (int | Unset):  Default: 0.
        score (float | None | Unset):
        last_run (None | str | Unset):
    """

    account_id: str
    benchmark: str | Unset = "cis_aws_v1.5"
    pass_count: int | Unset = 0
    fail_count: int | Unset = 0
    score: float | None | Unset = UNSET
    last_run: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        benchmark = self.benchmark

        pass_count = self.pass_count

        fail_count = self.fail_count

        score: float | None | Unset
        if isinstance(self.score, Unset):
            score = UNSET
        else:
            score = self.score

        last_run: None | str | Unset
        if isinstance(self.last_run, Unset):
            last_run = UNSET
        else:
            last_run = self.last_run

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
            }
        )
        if benchmark is not UNSET:
            field_dict["benchmark"] = benchmark
        if pass_count is not UNSET:
            field_dict["pass_count"] = pass_count
        if fail_count is not UNSET:
            field_dict["fail_count"] = fail_count
        if score is not UNSET:
            field_dict["score"] = score
        if last_run is not UNSET:
            field_dict["last_run"] = last_run

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        account_id = d.pop("account_id")

        benchmark = d.pop("benchmark", UNSET)

        pass_count = d.pop("pass_count", UNSET)

        fail_count = d.pop("fail_count", UNSET)

        def _parse_score(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        score = _parse_score(d.pop("score", UNSET))

        def _parse_last_run(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_run = _parse_last_run(d.pop("last_run", UNSET))

        benchmark_in = cls(
            account_id=account_id,
            benchmark=benchmark,
            pass_count=pass_count,
            fail_count=fail_count,
            score=score,
            last_run=last_run,
        )

        benchmark_in.additional_properties = d
        return benchmark_in

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
