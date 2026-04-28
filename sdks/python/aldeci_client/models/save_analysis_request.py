from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.save_analysis_request_payload_type_0 import SaveAnalysisRequestPayloadType0


T = TypeVar("T", bound="SaveAnalysisRequest")


@_attrs_define
class SaveAnalysisRequest:
    """Payload for save-analysis.

    One of ``payload`` (JSON dict) or ``payload_base64`` (base64-encoded
    UTF-8 JSON) must be supplied. ``payload_base64`` is provided so clients
    that need to send multipart-adjacent content (raw scanner output) can
    wrap it without escaping. The server always stores the decoded dict.

        Attributes:
            repo_path (str):
            payload (None | SaveAnalysisRequestPayloadType0 | Unset):
            payload_base64 (None | str | Unset):
    """

    repo_path: str
    payload: None | SaveAnalysisRequestPayloadType0 | Unset = UNSET
    payload_base64: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.save_analysis_request_payload_type_0 import SaveAnalysisRequestPayloadType0

        repo_path = self.repo_path

        payload: dict[str, Any] | None | Unset
        if isinstance(self.payload, Unset):
            payload = UNSET
        elif isinstance(self.payload, SaveAnalysisRequestPayloadType0):
            payload = self.payload.to_dict()
        else:
            payload = self.payload

        payload_base64: None | str | Unset
        if isinstance(self.payload_base64, Unset):
            payload_base64 = UNSET
        else:
            payload_base64 = self.payload_base64

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if payload is not UNSET:
            field_dict["payload"] = payload
        if payload_base64 is not UNSET:
            field_dict["payload_base64"] = payload_base64

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.save_analysis_request_payload_type_0 import SaveAnalysisRequestPayloadType0

        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        def _parse_payload(data: object) -> None | SaveAnalysisRequestPayloadType0 | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                payload_type_0 = SaveAnalysisRequestPayloadType0.from_dict(data)

                return payload_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | SaveAnalysisRequestPayloadType0 | Unset, data)

        payload = _parse_payload(d.pop("payload", UNSET))

        def _parse_payload_base64(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        payload_base64 = _parse_payload_base64(d.pop("payload_base64", UNSET))

        save_analysis_request = cls(
            repo_path=repo_path,
            payload=payload,
            payload_base64=payload_base64,
        )

        save_analysis_request.additional_properties = d
        return save_analysis_request

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
