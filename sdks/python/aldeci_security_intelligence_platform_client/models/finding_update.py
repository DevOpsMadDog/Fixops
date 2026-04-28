from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.finding_status import FindingStatus
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.finding_update_metadata_type_0 import FindingUpdateMetadataType0


T = TypeVar("T", bound="FindingUpdate")


@_attrs_define
class FindingUpdate:
    """Request model for updating a finding.

    Attributes:
        status (FindingStatus | None | Unset):
        metadata (FindingUpdateMetadataType0 | None | Unset):
    """

    status: FindingStatus | None | Unset = UNSET
    metadata: FindingUpdateMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.finding_update_metadata_type_0 import FindingUpdateMetadataType0

        status: None | str | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, FindingStatus):
            status = self.status.value
        else:
            status = self.status

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, FindingUpdateMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if status is not UNSET:
            field_dict["status"] = status
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.finding_update_metadata_type_0 import FindingUpdateMetadataType0

        d = dict(src_dict)

        def _parse_status(data: object) -> FindingStatus | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                status_type_0 = FindingStatus(data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FindingStatus | None | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_metadata(data: object) -> FindingUpdateMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = FindingUpdateMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(FindingUpdateMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        finding_update = cls(
            status=status,
            metadata=metadata,
        )

        finding_update.additional_properties = d
        return finding_update

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
