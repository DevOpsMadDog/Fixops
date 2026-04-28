from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.score_req_signals import ScoreReqSignals


T = TypeVar("T", bound="ScoreReq")


@_attrs_define
class ScoreReq:
    """
    Attributes:
        package_purl (str):
        org_id (str | Unset):  Default: 'default'.
        signals (ScoreReqSignals | Unset):
    """

    package_purl: str
    org_id: str | Unset = "default"
    signals: ScoreReqSignals | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        package_purl = self.package_purl

        org_id = self.org_id

        signals: dict[str, Any] | Unset = UNSET
        if not isinstance(self.signals, Unset):
            signals = self.signals.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "package_purl": package_purl,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if signals is not UNSET:
            field_dict["signals"] = signals

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.score_req_signals import ScoreReqSignals

        d = dict(src_dict)
        package_purl = d.pop("package_purl")

        org_id = d.pop("org_id", UNSET)

        _signals = d.pop("signals", UNSET)
        signals: ScoreReqSignals | Unset
        if isinstance(_signals, Unset):
            signals = UNSET
        else:
            signals = ScoreReqSignals.from_dict(_signals)

        score_req = cls(
            package_purl=package_purl,
            org_id=org_id,
            signals=signals,
        )

        score_req.additional_properties = d
        return score_req

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
