from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WebhookResponse")


@_attrs_define
class WebhookResponse:
    """Response body for the /webhook endpoint.

    Attributes:
        received (bool | Unset):  Default: True.
        commit_sha (None | str | Unset):
        analyses_count (int | Unset):  Default: 0.
        highest_risk (str | Unset):  Default: 'COSMETIC'.
    """

    received: bool | Unset = True
    commit_sha: None | str | Unset = UNSET
    analyses_count: int | Unset = 0
    highest_risk: str | Unset = "COSMETIC"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        received = self.received

        commit_sha: None | str | Unset
        if isinstance(self.commit_sha, Unset):
            commit_sha = UNSET
        else:
            commit_sha = self.commit_sha

        analyses_count = self.analyses_count

        highest_risk = self.highest_risk

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if received is not UNSET:
            field_dict["received"] = received
        if commit_sha is not UNSET:
            field_dict["commit_sha"] = commit_sha
        if analyses_count is not UNSET:
            field_dict["analyses_count"] = analyses_count
        if highest_risk is not UNSET:
            field_dict["highest_risk"] = highest_risk

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        received = d.pop("received", UNSET)

        def _parse_commit_sha(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        commit_sha = _parse_commit_sha(d.pop("commit_sha", UNSET))

        analyses_count = d.pop("analyses_count", UNSET)

        highest_risk = d.pop("highest_risk", UNSET)

        webhook_response = cls(
            received=received,
            commit_sha=commit_sha,
            analyses_count=analyses_count,
            highest_risk=highest_risk,
        )

        webhook_response.additional_properties = d
        return webhook_response

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
